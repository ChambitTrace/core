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
)

// C 로더가 보내는 유연한 JSON 구조를 받기 위한 구조체
type EventLog struct {
	Type     string  `json:"type"`
	Pid      uint32  `json:"pid"`
	Comm     string  `json:"comm"`
	CgroupID uint64  `json:"cgroup_id"`
	Filename *string `json:"filename,omitempty"`
	ParentPid *uint32 `json:"parent_pid,omitempty"`
	ChildPid  *uint32 `json:"child_pid,omitempty"`
	Mode      *uint32 `json:"mode,omitempty"`
	UID       *uint32 `json:"uid,omitempty"`
	GID       *uint32 `json:"gid,omitempty"`
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
	// --- 설정 완료 ---

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
		for scanner.Scan() {
			var e EventLog
			if err := json.Unmarshal(scanner.Bytes(), &e); err != nil {
				log.Printf("JSON 파싱 에러: %v, 받은 데이터: %s", err, scanner.Text())
				continue
			}

			podContext := getPodInfo(podLister, e.CgroupID, e.Pid)

			logString := fmt.Sprintf("%-15s | %-40s | PID: %-6d | Comm: %-15s |", e.Type, podContext, e.Pid, e.Comm)

			// 이벤트 타입에 따라 상세 정보 추가
			switch e.Type {
			case "EXEC", "OPEN", "MOUNT":
				if e.Filename != nil {
					logString += fmt.Sprintf(" File: %s", *e.Filename)
				}
			case "FORK_CLONE":
				if e.ParentPid != nil && e.ChildPid != nil {
					logString += fmt.Sprintf(" Parent PID: %d -> Child PID: %d", *e.ParentPid, *e.ChildPid)
				}
			case "CHMOD":
				details := ""
				if e.Filename != nil {
					details += fmt.Sprintf(" File: %s", *e.Filename)
				}
				if e.Mode != nil {
					details += fmt.Sprintf(" Mode: %#o", *e.Mode)
				}
				logString += details
			case "CHOWN":
				details := ""
				if e.Filename != nil {
					details += fmt.Sprintf(" File: %s", *e.Filename)
				}
				if e.UID != nil {
					details += fmt.Sprintf(" UID: %d", *e.UID)
				}
				if e.GID != nil {
					details += fmt.Sprintf(" GID: %d", *e.GID)
				}
				logString += details
			case "SETUID":
				if e.UID != nil {
					logString += fmt.Sprintf(" UID: %d", *e.UID)
				}
			case "SETGID":
				if e.GID != nil {
					logString += fmt.Sprintf(" GID: %d", *e.GID)
				}
			}
			
			log.Println(logString)
		}
	}()

	<-sig
	log.Println("\n프로그램을 종료합니다...")
}