package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corev1listers "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"

	"github.com/segmentio/kafka-go"
)

// C 로더가 보내는 유연한 JSON 구조를 받기 위한 구조체
type EventLog struct {
	Type      string  `json:"type"`
	Pid       uint32  `json:"pid"`
	Comm      string  `json:"comm"`
	CgroupID  uint64  `json:"cgroup_id"`
	Filename  *string `json:"filename,omitempty"`
	ParentPid *uint32 `json:"parent_pid,omitempty"`
	ChildPid  *uint32 `json:"child_pid,omitempty"`
	Mode      *uint32 `json:"mode,omitempty"`
	UID       *uint32 `json:"uid,omitempty"`
	GID       *uint32 `json:"gid,omitempty"`
}

// Kafka로 보낼 EnrichedEventLog 구조체
type EnrichedEventLog struct {
	EventLog
	PodContext string `json:"pod_context"`
	Timestamp  string `json:"timestamp"`
}

// cgroup ID를 키로 사용하여 Pod 정보를 캐싱
var infoCache = &sync.Map{}

// Pod UID를 추출하기 위한 정규식, cgroup v2 경로 형식에 맞춰 조정
var podUIDRegex = regexp.MustCompile(`([a-f0-9]{8}[-_][a-f0-9]{4}[-_][a-f0-9]{4}[-_][a-f0-9]{4}[-_][a-f0-9]{12})`)

// [수정됨] 새로운 정규식 및 UID 변환 로직이 적용된 getPodInfo 함수
func getPodInfo(podLister corev1listers.PodLister, cgroupID uint64, pid uint32) string {
	if cgroupID == 0 {
		return "[Host Process]"
	}
	if cachedInfo, found := infoCache.Load(cgroupID); found {
		return cachedInfo.(string)
	}

	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	content, err := os.ReadFile(cgroupPath)
	if err != nil {
		return "[Host Process]"
	}

	// 새로운 정규식을 사용하여 Pod UID 추출
	matches := podUIDRegex.FindStringSubmatch(string(content))
	if len(matches) < 2 {
		infoCache.Store(cgroupID, "[Host Process/Unknown Container]")
		return "[Host Process/Unknown Container]"
	}

	podUIDFromCgroup := matches[1]
	// [핵심 추가!] cgroup에서 추출한 UID의 언더스코어(_)를 하이픈(-)으로 변경
	podUID := strings.ReplaceAll(podUIDFromCgroup, "_", "-")

	allPods, err := podLister.List(labels.Everything())
	if err != nil {
		log.Printf("Error listing pods from lister: %v", err)
		return "[Error Listing Pods]"
	}

	var podInfo string = "[Pod: Not Found]"
	for _, pod := range allPods {
		if string(pod.ObjectMeta.UID) == podUID {
			podInfo = fmt.Sprintf("[Pod: %s/%s]", pod.Namespace, pod.Name)
			break
		}
	}

	infoCache.Store(cgroupID, podInfo)
	return podInfo
}

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// --- Kubernetes 클라이언트 및 Informer 설정 ---
	config, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("클러스터 내부 구성을 가져오는 데 실패했습니다: %v. 이 프로그램은 Pod 내부에서 실행되어야 합니다.", err)
	}
	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		log.Fatalf("Kubernetes 클라이언트셋 생성 실패: %v", err)
	}

	factory := informers.NewSharedInformerFactory(clientset, 30*time.Minute)
	podInformer := factory.Core().V1().Pods()
	podLister := podInformer.Lister()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go factory.Start(ctx.Done())

	log.Println("Waiting for informer caches to sync...")
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.Informer().HasSynced) {
		log.Fatalf("Timed out waiting for caches to sync")
	}
	log.Println("Informer caches synced successfully.")

	// --- Kafka Writer 설정  ---
	kafkaBrokers := os.Getenv("KAFKA_BROKERS")
	kafkaTopic := os.Getenv("KAFKA_TOPIC")
	var writer *kafka.Writer
	kafkaEnabled := kafkaBrokers != "" && kafkaTopic != ""
	if kafkaEnabled {
		writer = kafka.NewWriter(kafka.WriterConfig{
			Brokers:  strings.Split(kafkaBrokers, ","),
			Topic:    kafkaTopic,
			Balancer: &kafka.LeastBytes{},
			// 배치 전송을 위해 Kafka 클라이언트 내부 옵션을 조정할 수 있습니다.
			BatchSize:    100,             // 배치 크기. 로그가 100개 모이면 전송
			BatchTimeout: 1 * time.Second, /// 배치 타임아웃. 1초마다 전송 시도
		})
		defer writer.Close()
		log.Printf("Kafka writer configured for topic '%s' on brokers: %s", kafkaTopic, kafkaBrokers)
	} else {
		log.Printf("Kafka disabled: set both KAFKA_BROKERS and KAFKA_TOPIC to enable forwarding")
	}

	cmd := exec.Command("../trace/loader")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalf("StdoutPipe 생성 실패: %v", err)
	}
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		log.Fatalf("C 로더 프로그램 시작 실패: %v", err)
	}
	log.Println("eBPF C 로더를 시작했습니다. 이벤트 수신 대기 중...")
	defer cmd.Process.Kill()

	// 이벤트 처리 로직을 배치 방식으로 변경합니다.
	go func() {
		scanner := bufio.NewScanner(stdout)

		const batchSize = 100
		flushFrequency := 1 * time.Second

		var messageBatch []kafka.Message
		ticker := time.NewTicker(flushFrequency)

		flushBatch := func() {
			if !kafkaEnabled || len(messageBatch) == 0 {
				return
			}
			err := writer.WriteMessages(context.Background(), messageBatch...)
			if err != nil {
				log.Printf("Failed to write %d messages to Kafka: %v", len(messageBatch), err)
			} else {
				log.Printf("Successfully wrote %d messages to Kafka.", len(messageBatch))
			}
			messageBatch = nil // 배치 초기화
		}

		defer ticker.Stop()

		for {
			// Non-blocking scan attempt
			if scanner.Scan() {
				var e EventLog
				if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
					log.Printf("JSON parsing error: %v, received data: %s", err, scanner.Text())
					continue
				}

				podContext := getPodInfo(podLister, e.CgroupID, e.Pid)
				enrichedLog := EnrichedEventLog{
					EventLog:   e,
					PodContext: podContext,
					Timestamp:  time.Now().UTC().Format(time.RFC3339),
				}
				if kafkaEnabled {
					jsonData, err := json.Marshal(enrichedLog)
					if err != nil {
						log.Printf("JSON marshalling error: %v", err)
						continue
					}
					messageBatch = append(messageBatch, kafka.Message{Value: jsonData})
				}

				// 콘솔에는 즉시 출력하여 실시간 확인 가능
				logString := fmt.Sprintf("%-15s | %-40s | PID: %-6d | Comm: %-15s", enrichedLog.Type, enrichedLog.PodContext, enrichedLog.Pid, enrichedLog.Comm)
				log.Println(logString)

				if kafkaEnabled && len(messageBatch) >= batchSize {
					flushBatch()
					// 타이머를 리셋하여 불필요한 즉시 flush 방지
					ticker.Reset(flushFrequency)
				}
			} else {
				// 스캐너가 멈췄을 때(EOF 또는 에러)
				flushBatch()
				if err := scanner.Err(); err != nil {
					log.Printf("Error reading from scanner: %v", err)
				}
				return
			}

			// Check for timeout flush
			select {
			case <-ticker.C:
				flushBatch()
			default:
				// non-blocking
			}
		}
	}()

	<-sig
	log.Println("\n프로그램을 종료합니다...")
}
