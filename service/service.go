package service

import (
	"bufio"
	"cmp"
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/SR-SHREYAS/network-security-scanner.git/config"
	"github.com/SR-SHREYAS/network-security-scanner.git/risk"
	"github.com/SR-SHREYAS/network-security-scanner.git/schema"
	"golang.org/x/sync/errgroup"
)

// // concurrent orchestration
// func ScanPorts(ctx context.Context, input string, workers int) (schema.ScanReport, error) {
// 	startTime := time.Now()

// 	tgt, err := ResolveTarget(ctx, input)
// 	if err != nil {
// 		return schema.ScanReport{}, err
// 	}
// 	target := tgt.IP.String() // everything below scans this one resolved IP

// 	resultChan := make(chan schema.ScanResult, len(schema.CommonPorts))
// 	semaphore := make(chan struct{}, workers)
// 	var wg sync.WaitGroup

// 	for _, port := range schema.CommonPorts {
// 		wg.Add(1)
// 		go func(p int) {
// 			defer wg.Done()
// 			semaphore <- struct{}{}
// 			defer func() { <-semaphore }()

// 			resultChan <- ScanPort(target, p, 2*time.Second)
// 		}(port)
// 	}

// 	wg.Wait()
// 	close(resultChan)

// 	duration := time.Since(startTime).String()
// 	riskSummary := schema.RiskSummary{}

// 	results := []schema.ScanResult{}
// 	for r := range resultChan {
// 		if r.State == schema.StateOpen {
// 			results = append(results, r)
// 			riskSummary.Add(r.RiskLevel)
// 		}
// 	}

// 	fmt.Println("\n=== Risk Summary ===")
// 	if riskSummary.Critical > 0 {
// 		fmt.Printf("  CRITICAL: %d (immediate action required)\n", riskSummary.Critical)
// 	}
// 	if riskSummary.High > 0 {
// 		fmt.Printf("  HIGH:     %d (address soon)\n", riskSummary.High)
// 	}
// 	if riskSummary.Medium > 0 {
// 		fmt.Printf("  MEDIUM:   %d (review recommended)\n", riskSummary.Medium)
// 	}
// 	if riskSummary.Low > 0 {
// 		fmt.Printf("  LOW:      %d (acceptable risk)\n", riskSummary.Low)
// 	}
// 	if riskSummary.Info > 0 {
// 		fmt.Printf("  INFO:     %d (informational)\n", riskSummary.Info)
// 	}

// 	report := schema.ScanReport{
// 		Target:      target,
// 		ResolvedIP:  target,
// 		Exposure:    tgt.Exposure,
// 		ScanTime:    startTime.Format(time.RFC3339),
// 		Duration:    duration,
// 		TotalPorts:  len(schema.CommonPorts),
// 		OpenPorts:   len(results),
// 		RiskSummary: riskSummary,
// 		Results:     results,
// 	}

// 	return report, nil
// }

// // single port
// func ScanPort(target string, port int, timeout time.Duration) schema.ScanResult {
// 	address := net.JoinHostPort(target, strconv.Itoa(port))
// 	conn, err := net.DialTimeout("tcp", address, timeout)
// 	if err != nil {
// 		return schema.ScanResult{Port: port, State: "closed"}
// 	}
// 	defer conn.Close()

// 	service := identifyService(port, "")
// 	banner := grabBanner(conn, port)
// 	if banner != "" {
// 		service = identifyService(port, banner)
// 	}

// 	level, reason := risk.Classify(service)

// 	return schema.ScanResult{
// 		Port:      port,
// 		State:     schema.StateOpen,
// 		Service:   service,
// 		Banner:    banner,
// 		RiskLevel: level,
// 		Reason:    reason,
// 	}
// }

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

func grabBanner(ctx context.Context, conn net.Conn, port int, timeout time.Duration) string {
	deadline := time.Now().Add(timeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}

	conn.SetDeadline(deadline)

	// if the scan is cancelled , unblock a pending read immediately
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()

	// request before HTTP service
	httpPorts := map[int]bool{80: true, 8080: true}
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

// func classifyRisk(port int, service string) schema.RiskLevel {
// 	switch port {
// 	case 21, 23:
// 		return schema.RiskCritical
// 	case 3389, 445, 80, 8080:
// 		return schema.RiskHigh
// 	case 1433, 3306, 5432, 135, 139:
// 		return schema.RiskMedium
// 	case 443, 8443, 22, 993, 995:
// 		return schema.RiskLow
// 	default:
// 		return schema.RiskInfo
// 	}
// }

// -----
type Scanner struct {
	Ports         []int
	DialTimeout   time.Duration
	BannerTimeout time.Duration
}

func NewScanner(cfg config.Config) *Scanner {
	return &Scanner{
		Ports:         schema.CommonPorts,
		DialTimeout:   cfg.DialTimeout,
		BannerTimeout: cfg.BannerTimeout,
	}
}

func (s *Scanner) Scan(ctx context.Context, input string, workers int) (schema.ScanReport, error) {
	startTime := time.Now()

	tgt, err := ResolveTarget(ctx, input)
	if err != nil {
		return schema.ScanReport{}, err
	}
	ip := tgt.IP.String()

	if workers < 1 {
		workers = 1 // errgroup treats a limit of 0 as "never run anything"
	}

	// One slot per port; each worker writes only its own index.
	// No channel or mutex needed, and the order is deterministic.
	scanned := make([]schema.ScanResult, len(s.Ports))

	var g errgroup.Group
	g.SetLimit(workers)
	for i, port := range s.Ports {
		if ctx.Err() != nil {
			break
		}
		g.Go(func() error {
			scanned[i] = s.scanPort(ctx, ip, port)
			return nil
		})
	}
	_ = g.Wait() // Wait gives the happens-before edge, so reading scanned is race-free

	if err := ctx.Err(); err != nil {
		return schema.ScanReport{}, err // cancelled or timed out: no partial report
	}

	duration := time.Since(startTime).String()
	riskSummary := schema.RiskSummary{}
	results := []schema.ScanResult{}
	var closed, filtered, errored int

	for _, r := range scanned {
		switch r.State {
		case schema.StateOpen:
			results = append(results, r)
			riskSummary.Add(r.RiskLevel)
		case schema.StateClosed:
			closed++
		case schema.StateFiltered:
			filtered++
		case schema.StateError:
			errored++
		}
	}

	slices.SortFunc(results, func(a, b schema.ScanResult) int {
		return cmp.Compare(a.Port, b.Port)
	})

	hostStatus := schema.HostUp
	if len(results)+closed == 0 {
		hostStatus = schema.HostNoResponse
	}

	return schema.ScanReport{
		Target:        tgt.Input,
		ResolvedIP:    ip,
		Exposure:      tgt.Exposure,
		ScanTime:      startTime.Format(time.RFC3339),
		Duration:      duration,
		TotalPorts:    len(s.Ports),
		OpenPorts:     len(results),
		ClosedPorts:   closed,
		FilteredPorts: filtered,
		ErrorPorts:    errored,
		HostStatus:    hostStatus,
		RiskSummary:   riskSummary,
		Results:       results,
	}, nil
}

func (s *Scanner) scanPort(ctx context.Context, ip string, port int) schema.ScanResult {
	d := net.Dialer{Timeout: s.DialTimeout}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return schema.ScanResult{Port: port, State: classifyDialError(err)}
	}
	defer conn.Close()

	service := identifyService(port, "")
	banner := grabBanner(ctx, conn, port, s.BannerTimeout)
	if banner != "" {
		service = identifyService(port, banner)
	}

	level, reason := risk.Classify(service)

	return schema.ScanResult{
		Port:      port,
		State:     schema.StateOpen,
		Service:   service,
		Banner:    banner,
		RiskLevel: level,
		Reason:    reason,
	}
}

func classifyDialError(err error) schema.PortState {
	var ne net.Error
	switch {
	case errors.Is(err, syscall.ECONNREFUSED):
		return schema.StateClosed
	case errors.As(err, &ne) && ne.Timeout():
		return schema.StateFiltered
	default:
		return schema.StateError
	}
}
