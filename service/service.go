package service

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/SR-SHREYAS/network-security-scanner.git/schema"
)

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

// single port
func ScanPort(target string, port int, timeout time.Duration) schema.ScanResult {
	address := fmt.Sprintf("%s:%d", target, port)
	conn, err := net.DialTimeout("tcp", address, timeout)
	if err != nil {
		return schema.ScanResult{Port: port, State: "closed"}
	}
	defer conn.Close()

	service := identifyService(port, "")
	banner := grabBanner(conn, port)
	if banner != "" {
		service = identifyService(port, banner)
	}

	return schema.ScanResult{
		Port:    port,
		State:   "open",
		Service: service,
		Banner:  banner,
	}
}

func identifyService(port int, banner string) string {
	// Check the banner text first for a more accurate identification
	if banner != "" {
		bannerLower := strings.ToLower(banner)
		switch {
		case strings.Contains(bannerLower, "ssh"):
			return "SSH"
		case strings.Contains(bannerLower, "http"):
			return "HTTP"
		case strings.Contains(bannerLower, "ftp"):
			return "FTP"
		case strings.Contains(bannerLower, "smtp"):
			return "SMTP"
		case strings.Contains(bannerLower, "mysql"):
			return "MySQL"
		case strings.Contains(bannerLower, "postgresql"):
			return "PostgreSQL"
		}
	}

	// Fall back to the port-to-service map if no banner match
	if name, ok := schema.ServiceMap[port]; ok {
		return name
	}
	return "Unknown"
}

func grabBanner(conn net.Conn, port int) string {
	// 3 second read deadline
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))

	// request before HTTP service
	httpPorts := map[int]bool{80: true, 8080: true, 8443: true, 443: true}
	if httpPorts[port] {
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
	}

	// Try reading the first line of the response
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil && banner == "" {
		// Fall back to raw byte read if line- based read fails
		buf := make([]byte, 1024)
		n, readErr := conn.Read(buf)
		if readErr != nil {
			return ""
		}
		banner = string(buf[:n])
	}

	// Clean and truncate long banners
	banner = strings.TrimSpace(banner)
	if len(banner) > 200 {
		banner = banner[:200]
	}
	return banner
}
