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
func ScanPorts(target string, workers int) schema.ScanReport {
	startTime := time.Now()

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

	duration := time.Since(startTime).String()
	riskSummary := schema.RiskSummary{}

	results := []schema.ScanResult{}
	for r := range resultChan {
		if r.State == schema.StateOpen {
			results = append(results, r)
			riskSummary.Add(r.RiskLevel)
		}
	}

	fmt.Println("\n=== Risk Summary ===")
	if riskSummary.Critical > 0 {
		fmt.Printf("  CRITICAL: %d (immediate action required)\n", riskSummary.Critical)
	}
	if riskSummary.High > 0 {
		fmt.Printf("  HIGH:     %d (address soon)\n", riskSummary.High)
	}
	if riskSummary.Medium > 0 {
		fmt.Printf("  MEDIUM:   %d (review recommended)\n", riskSummary.Medium)
	}
	if riskSummary.Low > 0 {
		fmt.Printf("  LOW:      %d (acceptable risk)\n", riskSummary.Low)
	}
	if riskSummary.Info > 0 {
		fmt.Printf("  INFO:     %d (informational)\n", riskSummary.Info)
	}

	report := schema.ScanReport{
		Target:      target,
		ScanTime:    startTime.Format(time.RFC3339),
		Duration:    duration,
		TotalPorts:  len(schema.CommonPorts),
		OpenPorts:   len(results),
		RiskSummary: riskSummary,
		Results:     results,
	}

	return report

}

// single port
func ScanPort(target string, port int, timeout time.Duration) schema.ScanResult {
	address := fmt.Sprintf("%s: %d", target, port)
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

	riskLevel := classifyRisk(port, service)

	return schema.ScanResult{
		Port:      port,
		State:     schema.StateOpen,
		Service:   service,
		Banner:    banner,
		RiskLevel: riskLevel,
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

func classifyRisk(port int, service string) schema.RiskLevel {
	switch port {
	case 21, 23:
		return schema.RiskCritical
	case 3389, 445, 80, 8080:
		return schema.RiskHigh
	case 1433, 3306, 5432, 135, 139:
		return schema.RiskMedium
	case 443, 8443, 22, 993, 995:
		return schema.RiskLow
	default:
		return schema.RiskInfo
	}
}
