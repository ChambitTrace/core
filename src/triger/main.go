package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"

	"github.com/aquasecurity/libbpfgo"
)

// [수정] C 코드의 event_type 열거형과 1:1 매칭
const (
	EventTypeExec uint32 = iota
	EventTypeExecveat
	EventTypeForkClone
	EventTypePtrace
	EventTypeOpen
	EventTypeOpenat
	EventTypeCreat
	EventTypeRead
	EventTypeWrite
	EventTypeChmod
	EventTypeFchmod
	EventTypeChown
	EventTypeMount
	EventTypeSetuid
	EventTypeSetgid
	EventTypeCapset
	EventTypeUnshare
	EventTypeSetns
	EventTypeInitModule
	EventTypeFinitModule
	EventTypeDeleteModule
	EventTypeBpf
)

// [수정] C 코드의 event 구조체와 동일하게 수정
type Event struct {
	CgroupId uint64
	Pid      uint32
	Comm     [16]byte
	Type     uint32
	Args     [128]byte // Union을 처리하기 위한 바이트 배열
}

var cgroupCache = &sync.Map{}

func getContainerInfo(cgroupId uint64, pid uint32) string {
	if cgroupId == 0 {
		return "[Host Process]"
	}
	if cachedInfo, found := cgroupCache.Load(cgroupId); found {
		return cachedInfo.(string)
	}
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	content, err := os.ReadFile(cgroupPath)
	if err != nil {
		return "[Host Process]"
	}
	re := regexp.MustCompile(`.*/pod[a-f0-9\-]+/([a-f0-9]{64})`)
	matches := re.FindStringSubmatch(string(content))
	var containerInfo string
	if len(matches) > 1 {
		containerIdShort := matches[1][:12]
		containerInfo = fmt.Sprintf("[Container: %s]", containerIdShort)
	} else if strings.Contains(string(content), "docker") {
		reDocker := regexp.MustCompile(`/docker/([a-f0-9]{64})`)
		matchesDocker := reDocker.FindStringSubmatch(string(content))
		if len(matchesDocker) > 1 {
			containerIdShort := matchesDocker[1][:12]
			containerInfo = fmt.Sprintf("[Container: %s]", containerIdShort)
		} else {
			containerInfo = "[Container: Unknown]"
		}
	} else {
		containerInfo = "[Host Process]"
	}
	cgroupCache.Store(cgroupId, containerInfo)
	return containerInfo
}

// [수정] 일반적인 sys_enter 트레이스포인트 연결 헬퍼
func attachSyscallTracepoint(bpfModule *libbpfgo.Module, syscallName string) {
	progName := fmt.Sprintf("tracepoint__syscalls__sys_enter_%s", syscallName)
	prog, err := bpfModule.GetProgram(progName)
	if err != nil {
		// 일부 시스템콜은 핸들러가 없을 수 있으므로 치명적 오류 대신 경고만 출력
		log.Printf("%s 프로그램을 찾을 수 없음: %v (정상일 수 있음)", progName, err)
		return
	}
	if _, err := prog.AttachTracepoint("syscalls", fmt.Sprintf("sys_enter_%s", syscallName)); err != nil {
		log.Fatalf("%s 트레이스포인트 연결 실패: %v", syscallName, err)
	}
	log.Printf("Syscall Tracepoint Attached: %s", syscallName)
}

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	bpfModule, err := libbpfgo.NewModuleFromFile("runtime_monitor.bpf.o")
	if err != nil {
		log.Fatalf("eBPF 모듈 로딩 실패: %v", err)
	}
	defer bpfModule.Close()

	if err := bpfModule.BPFLoadObject(); err != nil {
		log.Fatalf("eBPF 오브젝트 커널 로딩 실패: %v", err)
	}

	// [수정] 모든 시스템 콜 목록
	syscallsToTrace := []string{
		"execve", "execveat", "ptrace", "open", "openat", "creat",
		"read", "write", "chmod", "fchmod", "chown", "mount", "setuid",
		"setgid", "capset", "unshare", "setns", "init_module",
		"finit_module", "delete_module", "bpf",
	}
	for _, syscall := range syscallsToTrace {
		attachSyscallTracepoint(bpfModule, syscall)
	}

	// [추가] fork/clone을 위한 별도 트레이스포인트 연결
	progFork, err := bpfModule.GetProgram("tracepoint__sched__sched_process_fork")
	if err != nil {
		log.Fatalf("sched_process_fork 프로그램 가져오기 실패: %v", err)
	}
	if _, err := progFork.AttachTracepoint("sched", "sched_process_fork"); err != nil {
		log.Fatalf("sched_process_fork 트레이스포인트 연결 실패: %v", err)
	}
	log.Printf("Scheduler Tracepoint Attached: sched_process_fork")

	eventsChannel := make(chan []byte)
	rb, err := bpfModule.InitRingBuf("events", eventsChannel)
	if err != nil {
		log.Fatalf("Ring Buffer 초기화 실패: %v", err)
	}

	rb.Start()
	log.Println("\neBPF 런타임 모니터 시작! (Ctrl+C로 종료)")

	go func() {
		for data := range eventsChannel {
			var e Event
			if err := binary.Read(bytes.NewReader(data), binary.LittleEndian, &e); err != nil {
				log.Printf("데이터 파싱 에러: %v", err)
				continue
			}

			comm := string(bytes.TrimRight(e.Comm[:], "\x00"))
			containerContext := getContainerInfo(e.CgroupId, e.Pid)

			// [수정] 모든 이벤트 타입에 대한 처리 로직 추가
			switch e.Type {
			// 프로세스
			case EventTypeExec, EventTypeExecveat:
				filename := string(bytes.TrimRight(e.Args[:], "\x00"))
				log.Printf("프로세스 실행 | %s | PID: %d | Comm: %s | Filename: %s", containerContext, e.Pid, comm, filename)
			case EventTypeForkClone:
				var childPid uint32
				binary.Read(bytes.NewReader(e.Args[:]), binary.LittleEndian, &childPid)
				log.Printf("프로세스 생성 | %s | Parent PID: %d (%s) -> Child PID: %d", containerContext, e.Pid, comm, childPid)
			case EventTypePtrace:
				log.Printf("프로세스 조작 시도 | %s | PID: %d | Comm: %s | Syscall: ptrace", containerContext, e.Pid, comm)
			
			// 파일 시스템
			case EventTypeOpen, EventTypeOpenat, EventTypeCreat:
				filename := string(bytes.TrimRight(e.Args[:], "\x00"))
				log.Printf("파일 열기/생성 | %s | PID: %d | Comm: %s | File: %s", containerContext, e.Pid, comm, filename)
			case EventTypeRead:
				log.Printf("파일 읽기 | %s | PID: %d | Comm: %s", containerContext, e.Pid, comm)
			case EventTypeWrite:
				log.Printf("파일 쓰기 | %s | PID: %d | Comm: %s", containerContext, e.Pid, comm)
			case EventTypeChmod, EventTypeFchmod:
				filename := string(bytes.TrimRight(e.Args[:], "\x00"))
				log.Printf("파일 권한 변경 | %s | PID: %d | Comm: %s | File: %s", containerContext, e.Pid, comm, filename)
			case EventTypeChown:
				filename := string(bytes.TrimRight(e.Args[:], "\x00"))
				log.Printf("파일 소유자 변경 | %s | PID: %d | Comm: %s | File: %s", containerContext, e.Pid, comm, filename)
			case EventTypeMount:
				log.Printf("파일시스템 마운트 | %s | PID: %d | Comm: %s", containerContext, e.Pid, comm)

			// 권한
			case EventTypeSetuid, EventTypeSetgid, EventTypeCapset:
				log.Printf("권한 변경 | %s | PID: %d | Comm: %s", containerContext, e.Pid, comm)
			case EventTypeUnshare, EventTypeSetns:
				log.Printf("컨테이너 탈출/격리 변경 시도 | %s | PID: %d | Comm: %s", containerContext, e.Pid, comm)

			// 커널 모듈 및 BPF
			case EventTypeInitModule, EventTypeFinitModule:
				log.Printf("커널 모듈 로드 시도 | %s | PID: %d | Comm: %s", containerContext, e.Pid, comm)
			case EventTypeDeleteModule:
				log.Printf("커널 모듈 제거 시도 | %s | PID: %d | Comm: %s", containerContext, e.Pid, comm)
			case EventTypeBpf:
				log.Printf("eBPF 프로그램 로드 시도 | %s | PID: %d | Comm: %s", containerContext, e.Pid, comm)
			}
		}
	}()

	<-sig
	rb.Stop()
	rb.Close()
	log.Println("\n프로그램을 종료합니다...")
}
