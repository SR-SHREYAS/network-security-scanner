package service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/SR-SHREYAS/network-security-scanner.git/schema"
)

var ErrInvalidTarget = errors.New("invalid target")

type Target struct {
	Input    string
	IP       net.IP
	Exposure schema.Exposure
}

func ResolveTarget(ctx context.Context, input string) (Target, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return Target{}, fmt.Errorf("%w: empty", ErrInvalidTarget)
	}

	ip := net.ParseIP(input)
	if ip == nil {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()

		addrs, err := net.DefaultResolver.LookupIPAddr(ctx, input)
		if err != nil || len(addrs) == 0 {
			return Target{}, fmt.Errorf("%w: cannot resolve %q", ErrInvalidTarget, input)
		}
		ip = pickIP(addrs)
	}

	if ip.IsUnspecified() || ip.IsMulticast() {
		return Target{}, fmt.Errorf("%w: %s is not a scannable address", ErrInvalidTarget, ip)
	}

	return Target{Input: input, IP: ip, Exposure: classifyExposure(ip)}, nil
}

// pickIP prefers IPv4, falling back to the first address returned.
func pickIP(addrs []net.IPAddr) net.IP {
	for _, a := range addrs {
		if a.IP.To4() != nil {
			return a.IP
		}
	}
	return addrs[0].IP
}

func classifyExposure(ip net.IP) schema.Exposure {
	switch {
	case ip.IsLoopback():
		return schema.ExposureLoopback
	case ip.IsPrivate(), ip.IsLinkLocalUnicast():
		return schema.ExposurePrivate
	default:
		return schema.ExposurePublic
	}
}
