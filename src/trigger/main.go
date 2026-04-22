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
	"strconv"
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
	PodContext  string `json:"pod_context"`
	Timestamp   string `json:"timestamp"`
	ClusterName string `json:"cluster_name,omitempty"`
	NodeName    string `json:"node_name,omitempty"`
	NodeIP      string `json:"node_ip,omitempty"`
}

type AgentConfig struct {
	KafkaBrokers      []string
	KafkaTopic        string
	KafkaBatchSize    int
	KafkaBatchTimeout time.Duration
	KafkaWriteTimeout time.Duration
	ClusterName       string
	NodeName          string
	NodeIP            string
}

const (
	defaultKafkaBatchSize      = 100
	defaultKafkaBatchTimeoutMs = 1000
	defaultKafkaWriteTimeoutMs = 5000
)

// cgroup ID를 키로 사용하여 Pod 정보를 캐싱
var infoCache = &sync.Map{}

// Pod UID를 추출하기 위한 정규식, cgroup v2 경로 형식에 맞춰 조정
var podUIDRegex = regexp.MustCompile(`([a-f0-9]{8}[-_][a-f0-9]{4}[-_][a-f0-9]{4}[-_][a-f0-9]{4}[-_][a-f0-9]{12})`)

func getEnvOrDefault(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func getEnvIntOrDefault(key string, fallback, minValue int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}

	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minValue {
		log.Printf("Invalid value for %s=%q. Using default: %d", key, value, fallback)
		return fallback
	}

	return parsed
}

func parseKafkaBrokers(raw string) []string {
	parts := strings.Split(raw, ",")
	brokers := make([]string, 0, len(parts))

	for _, part := range parts {
		broker := strings.TrimSpace(part)
		if broker != "" {
			brokers = append(brokers, broker)
		}
	}

	return brokers
}

func loadAgentConfig() AgentConfig {
	batchTimeoutMs := getEnvIntOrDefault("KAFKA_BATCH_TIMEOUT_MS", defaultKafkaBatchTimeoutMs, 1)
	writeTimeoutMs := getEnvIntOrDefault("KAFKA_WRITE_TIMEOUT_MS", defaultKafkaWriteTimeoutMs, 1)

	return AgentConfig{
		KafkaBrokers:      parseKafkaBrokers(os.Getenv("KAFKA_BROKERS")),
		KafkaTopic:        strings.TrimSpace(os.Getenv("KAFKA_TOPIC")),
		KafkaBatchSize:    getEnvIntOrDefault("KAFKA_BATCH_SIZE", defaultKafkaBatchSize, 1),
		KafkaBatchTimeout: time.Duration(batchTimeoutMs) * time.Millisecond,
		KafkaWriteTimeout: time.Duration(writeTimeoutMs) * time.Millisecond,
		ClusterName:       getEnvOrDefault("CLUSTER_NAME", "homelab-k3s"),
		NodeName:          getEnvOrDefault("NODE_NAME", "unknown-node"),
		NodeIP:            getEnvOrDefault("NODE_IP", "unknown-ip"),
	}
}

// 새로운 정규식 및 UID 변환 로직이 적용된 getPodInfo 함수
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

	matches := podUIDRegex.FindStringSubmatch(string(content))
	if len(matches) < 2 {
		infoCache.Store(cgroupID, "[Host Process/Unknown Container]")
		return "[Host Process/Unknown Container]"
	}

	podUIDFromCgroup := matches[1]
	podUID := strings.ReplaceAll(podUIDFromCgroup, "_", "-")

	allPods, err := podLister.List(labels.Everything())
	if err != nil {
		log.Printf("Error listing pods from lister: %v", err)
		return "[Error Listing Pods]"
	}

	podInfo := "[Pod: Not Found]"
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

	config := loadAgentConfig()

	// --- Kubernetes 클라이언트 및 Informer 설정 ---
	kubeConfig, err := rest.InClusterConfig()
	if err != nil {
		log.Fatalf("클러스터 내부 구성을 가져오는 데 실패했습니다: %v. 이 프로그램은 Pod 내부에서 실행되어야 합니다.", err)
	}
	clientset, err := kubernetes.NewForConfig(kubeConfig)
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

	// --- Kafka Writer 설정 ---
	kafkaEnabled := len(config.KafkaBrokers) > 0 && config.KafkaTopic != ""
	var writer *kafka.Writer
	if kafkaEnabled {
		writer = kafka.NewWriter(kafka.WriterConfig{
			Brokers:      config.KafkaBrokers,
			Topic:        config.KafkaTopic,
			Balancer:     &kafka.LeastBytes{},
			BatchSize:    config.KafkaBatchSize,
			BatchTimeout: config.KafkaBatchTimeout,
			RequiredAcks: int(kafka.RequireOne),
		})
		defer writer.Close()
		log.Printf(
			"Kafka writer configured. topic=%s brokers=%s batch_size=%d batch_timeout=%s write_timeout=%s",
			config.KafkaTopic,
			strings.Join(config.KafkaBrokers, ","),
			config.KafkaBatchSize,
			config.KafkaBatchTimeout,
			config.KafkaWriteTimeout,
		)
	} else {
		log.Printf("Kafka disabled: set KAFKA_BROKERS and KAFKA_TOPIC to enable forwarding")
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

	go func() {
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)

		batchSize := config.KafkaBatchSize
		flushFrequency := config.KafkaBatchTimeout
		messageBatch := make([]kafka.Message, 0, batchSize)
		ticker := time.NewTicker(flushFrequency)

		flushBatch := func() {
			if !kafkaEnabled || len(messageBatch) == 0 {
				return
			}

			writeCtx, writeCancel := context.WithTimeout(context.Background(), config.KafkaWriteTimeout)
			err := writer.WriteMessages(writeCtx, messageBatch...)
			writeCancel()
			if err != nil {
				log.Printf("Failed to write %d messages to Kafka: %v", len(messageBatch), err)
			} else {
				log.Printf("Successfully wrote %d messages to Kafka.", len(messageBatch))
			}

			messageBatch = messageBatch[:0]
		}

		defer ticker.Stop()

		for {
			if scanner.Scan() {
				var e EventLog
				if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
					log.Printf("JSON parsing error: %v, received data: %s", err, scanner.Text())
					continue
				}

				podContext := getPodInfo(podLister, e.CgroupID, e.Pid)
				enrichedLog := EnrichedEventLog{
					EventLog:    e,
					PodContext:  podContext,
					Timestamp:   time.Now().UTC().Format(time.RFC3339),
					ClusterName: config.ClusterName,
					NodeName:    config.NodeName,
					NodeIP:      config.NodeIP,
				}

				if kafkaEnabled {
					jsonData, err := json.Marshal(enrichedLog)
					if err != nil {
						log.Printf("JSON marshalling error: %v", err)
						continue
					}

					msg := kafka.Message{Value: jsonData}
					if config.NodeName != "" {
						msg.Key = []byte(config.NodeName)
					}
					messageBatch = append(messageBatch, msg)
				}

				logString := fmt.Sprintf(
					"%-15s | Node: %-20s | %-40s | PID: %-6d | Comm: %-15s",
					enrichedLog.Type,
					enrichedLog.NodeName,
					enrichedLog.PodContext,
					enrichedLog.Pid,
					enrichedLog.Comm,
				)
				log.Println(logString)

				if kafkaEnabled && len(messageBatch) >= batchSize {
					flushBatch()
					ticker.Reset(flushFrequency)
				}
			} else {
				flushBatch()
				if err := scanner.Err(); err != nil {
					log.Printf("Error reading from scanner: %v", err)
				}
				return
			}

			select {
			case <-ticker.C:
				flushBatch()
			default:
			}
		}
	}()

	<-sig
	log.Println("\n프로그램을 종료합니다...")
}
