package service

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/SR-SHREYAS/network-security-scanner.git/schema"
)

func TestClassifyDialError(t *testing.T) {
	refused := &net.OpError{Op: "dial", Err: os.NewSyscallError("connect", syscall.ECONNREFUSED)}

	tests := []struct {
		name string
		err  error
		want schema.PortState
	}{
		{"refused", refused, schema.StateClosed},
		{"timeout", context.DeadlineExceeded, schema.StateFiltered},
		{"other", syscall.EMFILE, schema.StateError},
	}
	for _, tt := range tests {
		if got := classifyDialError(tt.err); got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.name, got, tt.want)
		}
	}
}

// openAndClosedPorts returns a port with a live listener that accepts and
// immediately closes (so banner reads end fast), and a port nothing listens on.
func openAndClosedPorts(t *testing.T) (open, closed int) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()

	l2, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed = l2.Addr().(*net.TCPAddr).Port
	l2.Close()

	return ln.Addr().(*net.TCPAddr).Port, closed
}

func TestScanPortOpenAndClosed(t *testing.T) {
	open, closed := openAndClosedPorts(t)
	s := &Scanner{DialTimeout: time.Second, BannerTimeout: time.Second}
	ctx := context.Background()

	if got := s.scanPort(ctx, "127.0.0.1", open); got.State != schema.StateOpen {
		t.Errorf("open port reported %s", got.State)
	}
	if got := s.scanPort(ctx, "127.0.0.1", closed); got.State != schema.StateClosed {
		t.Errorf("closed port reported %s", got.State)
	}
}

func TestScanCounts(t *testing.T) {
	open, closed := openAndClosedPorts(t)
	s := &Scanner{
		Ports:         []int{open, closed},
		DialTimeout:   time.Second,
		BannerTimeout: time.Second,
	}

	rep, err := s.Scan(context.Background(), "127.0.0.1", 2)
	if err != nil {
		t.Fatal(err)
	}
	if rep.TotalPorts != 2 || rep.OpenPorts != 1 || rep.ClosedPorts != 1 {
		t.Errorf("unexpected counts: %+v", rep)
	}
	if rep.HostStatus != schema.HostUp {
		t.Errorf("host status = %s, want up", rep.HostStatus)
	}
}

func TestScanRespectsCancellation(t *testing.T) {
	// A server that accepts and then never writes makes the banner read block.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	defer close(done)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		<-done
		c.Close()
	}()

	s := &Scanner{
		Ports:         []int{ln.Addr().(*net.TCPAddr).Port},
		DialTimeout:   time.Second,
		BannerTimeout: 10 * time.Second,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	_, err = s.Scan(ctx, "127.0.0.1", 1)

	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected DeadlineExceeded, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("scan ignored cancellation, took %s", elapsed)
	}
}
