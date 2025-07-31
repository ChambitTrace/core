package main

import (
	"bufio"
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
)

// C 로더가 보내는 유연한 JSON 구조를 받기 위한 구조체
// 필드가 없는 경우에도 파싱 에러가 나지 않도록 포인터와 omitempty 사용
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

var cgroupCache = &sync.Map{}

func getContainerInfo(cgroupId uint64, pid uint32) string {
	// (이전과 동일, 수정 없음)
	if cgroupId == 0 {
		return "[Host Process]"
	}
	if cachedInfo, found := cgroupCache.Load(cgroupId); found {
		return cachedInfo.(string)
	}
	cgroupPath := fmt.Sprintf("/proc/%d/cgroup", pid)
	content, err := os.ReadFile(cgroupPath)
	if err != nil {
		if cachedInfo, found := cgroupCache.Load(cgroupId); found {
			return cachedInfo.(string)
		}
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

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

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

			containerContext := getContainerInfo(e.CgroupID, e.Pid)
			logString := fmt.Sprintf("%-15s | %s | PID: %-6d | Comm: %-15s |", e.Type, containerContext, e.Pid, e.Comm)

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
				// READ, WRITE, PTRACE, CAPSET, UNSHARE, SETNS, MODULE, BPF 등은 추가 정보 없음
			}
			log.Println(logString)
		}
	}()

	<-sig
	log.Println("\n프로그램을 종료합니다...")
}
