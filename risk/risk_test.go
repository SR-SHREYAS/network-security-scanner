package risk_test

import (
	"testing"

	"github.com/SR-SHREYAS/network-security-scanner.git/risk"
	"github.com/SR-SHREYAS/network-security-scanner.git/schema"
)

func TestEveryKnownServiceHasRule(t *testing.T) {
	for port, service := range schema.ServiceMap {
		if !risk.Has(service) {
			t.Errorf("port %d: Service %s has no risk rule defined", port, service)
		}
	}
}

func TestClassify(t *testing.T) {
	tests := []struct {
		service string
		want    schema.RiskLevel
	}{
		{"Telnet", schema.RiskCritical},
		{"Redis", schema.RiskHigh},
		{"PostgreSQL", schema.RiskMedium},
		{"SSH", schema.RiskLow},
		{"UnknownService", schema.RiskInfo},
	}
	for _, tt := range tests {
		got, reason := risk.Classify(tt.service)
		if got != tt.want {
			t.Errorf("Classify(%s) = %v, want %s", tt.service, got, tt.want)
		}
		if reason == "" {
			t.Error("classify returned an empty reason for service", tt.service)
		}
	}
}
