package service

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/SR-SHREYAS/network-security-scanner.git/schema"
)

func TestClassifyExposure(t *testing.T) {
	tests := []struct {
		ip   string
		want schema.Exposure
	}{
		{"127.0.0.1", schema.ExposureLoopback},
		{"::1", schema.ExposureLoopback},
		{"192.168.1.10", schema.ExposurePrivate},
		{"10.0.0.5", schema.ExposurePrivate},
		{"172.16.0.1", schema.ExposurePrivate},
		{"169.254.1.1", schema.ExposurePrivate},
		{"8.8.8.8", schema.ExposurePublic},
	}
	for _, tt := range tests {
		if got := classifyExposure(net.ParseIP(tt.ip)); got != tt.want {
			t.Errorf("%s: got %s, want %s", tt.ip, got, tt.want)
		}
	}
}

func TestResolveTargetInvalid(t *testing.T) {
	for _, in := range []string{"", "  ", "0.0.0.0", "224.0.0.1", "nothing.invalid"} {
		_, err := ResolveTarget(context.Background(), in)
		if !errors.Is(err, ErrInvalidTarget) {
			t.Errorf("%q: expected ErrInvalidTarget, got %v", in, err)
		}
	}
}

func TestResolveTargetLiteral(t *testing.T) {
	tgt, err := ResolveTarget(context.Background(), "127.0.0.1")
	if err != nil || tgt.Exposure != schema.ExposureLoopback {
		t.Fatalf("got %+v, %v", tgt, err)
	}
}
