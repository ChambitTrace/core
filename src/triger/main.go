package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/segmentio/kafka-go"
)

type Event struct {
    Timestamp   string `json:"timestamp"`
    PID         int    `json:"pid"`
    Path        string `json:"path"`
    Node        string `json:"node"`
    ContainerID string `json:"container_id,omitempty"`
    Pod         string `json:"pod,omitempty"`
    Namespace   string `json:"namespace,omitempty"`
    Image       string `json:"image,omitempty"`
}

func main() {
    // 현재 위치의 노드 이름 가져오기
    hostname, err := os.Hostname()
    if err != nil {
        log.Fatalf("failed to get hostname: %v", err)
    }

    // Kafka writer
    writer := kafka.NewWriter(kafka.WriterConfig{
        Brokers:  []string{"172.31.39.174:9092"},
        Topic:    "ebpf-log",
        Balancer: &kafka.LeastBytes{},
    })
    defer writer.Close()

    // loader 파일 존재 확인
    if _, err := os.Stat("../trace/loader"); os.IsNotExist(err) {
        // 파일이 없으면 make 실행
        cmdMake := exec.Command("make")
        cmdMake.Dir = "../trace"
        cmdMake.Stdout = os.Stdout
        cmdMake.Stderr = os.Stderr
        if err := cmdMake.Run(); err != nil {
            log.Fatalf("failed to run make: %v", err)
        }
    }

    // 기존 loader 실행 코드
    cmd := exec.Command("../trace/loader")
    stdout, err := cmd.StdoutPipe()
    if err != nil {
        log.Fatalf("failed to get stdout: %v", err)
    }

    if err := cmd.Start(); err != nil {
        log.Fatalf("failed to start loader: %v", err)
    }

    scanner := bufio.NewScanner(stdout)
    for scanner.Scan() {
        line := scanner.Text()

        if !strings.Contains(line, "{") {
            continue
        }

        var event Event
        if err := json.Unmarshal([]byte(line), &event); err != nil {
            log.Printf("invalid json: %s", line)
            continue
        }
        event.Node = hostname
        

        // Insert dummy container metadata fields to simulate a resolved container context
        event.ContainerID = "dummy-container-id"
        event.Pod = "vex-oci-attach-846c94769d-cwgz9"
        event.Namespace = "default"
        event.Image = "ghcr.io/anchore/test-images/vex-oci-attach:51198f0"

        // 현재 노드가 아니면 전송하지 않음
        if event.Node != hostname {
            continue
        }

        // cgroup 확인
        // cgroupPath := fmt.Sprintf("/proc/%d/cgroup", event.PID)
        // data, err := os.ReadFile(cgroupPath)
        // if err != nil {
        //     log.Printf("unable to read cgroup for pid %d: %v", event.PID, err)
        //     continue
        // }
        // fmt.Printf("[DEBUG] cgroup for pid %d:\n%s\n", event.PID, string(data))
        
        msgBytes, _ := json.Marshal(event)
            fmt.Println("[DEBUG] Sending to Kafka:", string(msgBytes))
            
            err = writer.WriteMessages(context.Background(),
                kafka.Message{
                    Key:   []byte(time.Now().Format(time.RFC3339Nano)),
                    Value: msgBytes,
                })
            if err != nil {
                log.Printf("failed to write to kafka: %v", err)
            }
    }

    if err := cmd.Wait(); err != nil {
        log.Fatalf("loader exited with error: %v", err)
    }
}