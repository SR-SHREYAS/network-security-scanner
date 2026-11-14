package service

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/SR-SHREYAS/network-security-scanner.git/schema"
)

// single port, restored as-is
func ScanPort(target string, port int, timeout time.Duration) schema.ScanResult {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return schema.ScanResult{Port: port, State: "closed"}
	}
	defer conn.Close()

	return schema.ScanResult{
		Port:    port,
		State:   "open",
		Service: identifyService(port, ""),
	}
}

// concurrent orchestration
func ScanPorts(target string, workers int) []schema.ScanResult {
	resultChan := make(chan schema.ScanResult, len(schema.CommonPorts))
	semaphore := make(chan struct{}, workers)
	var wg sync.WaitGroup

	for _, port := range schema.CommonPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			resultChan <- ScanPort(target, p, 2*time.Second)
		}(port)
	}

	wg.Wait()
	close(resultChan)

	results := []schema.ScanResult{}
	for r := range resultChan {
		if r.State == "open" {
			results = append(results, r)
		}
	}
	return results
}

func identifyService(port int, banner string) string {
	if name, ok := schema.ServiceMap[port]; ok {
		return name
	}
	return "Unknown"
}
