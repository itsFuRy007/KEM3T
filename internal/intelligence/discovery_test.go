package intelligence

import (
	"strings"
	"testing"
)

func TestDiscoveryEngineSurfacesConvergentSignals(t *testing.T) {
	engine := &DiscoveryEngine{}
	correlations := []Correlation{
		{
			ID: "shared-ip:203.0.113.10", Type: CorrelationSharedIPAddress,
			Entities: []string{"example.com", "api.example.net"}, SharedValue: "203.0.113.10",
			EvidenceIDs: []string{"e-ip"}, ConfidenceScope: "OBSERVED_SHARED_ADDRESS",
		},
		{
			ID: "shared-tls-cert:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Type: CorrelationSharedTLSCertificateFingerprint,
			Entities: []string{"example.com", "api.example.net"}, SharedValue: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			EvidenceIDs: []string{"e-tls"}, ConfidenceScope: "OBSERVED_SHARED_CERTIFICATE_FINGERPRINT",
		},
	}

	results, err := engine.Discover(correlations, "example.com")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Discover() returned %d discoveries, want 1", len(results))
	}
	got := results[0]
	if got.Type != DiscoveryConvergentInfrastructure {
		t.Fatalf("unexpected type %q", got.Type)
	}
	if got.SignalDiversity != 2 {
		t.Fatalf("signal diversity = %d, want 2", got.SignalDiversity)
	}
	if len(got.CorrelationIDs) != 2 {
		t.Fatalf("correlation IDs = %d, want 2", len(got.CorrelationIDs))
	}
	if got.Confidence != "LOW" {
		t.Fatalf("confidence = %q, want LOW until source independence and temporal independence are established", got.Confidence)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestDiscoveryEngineDoesNotTreatSameDimensionAsConvergence(t *testing.T) {
	engine := &DiscoveryEngine{}
	correlations := []Correlation{
		{ID: "shared-ip:203.0.113.10", Type: CorrelationSharedIPAddress, Entities: []string{"example.com", "api.example.net"}, SharedValue: "203.0.113.10", EvidenceIDs: []string{"e1"}},
		{ID: "shared-ip:203.0.113.11", Type: CorrelationSharedIPAddress, Entities: []string{"example.com", "api.example.net"}, SharedValue: "203.0.113.11", EvidenceIDs: []string{"e2"}},
	}
	results, err := engine.Discover(correlations, "example.com")
	if err != nil {
		t.Fatalf("Discover() error = %v", err)
	}
	if len(results) != 0 {
		t.Fatalf("Discover() returned %d discoveries, want 0", len(results))
	}
}


func TestDiscoveryEngineDoesNotCountSameUnderlyingDimensionTwice(t *testing.T) {
	engine := &DiscoveryEngine{}
	tests := []struct {
		name string
		correlations []Correlation
	}{
		{
			name: "current and historical address",
			correlations: []Correlation{
				{ID: "current", Type: CorrelationSharedIPAddress, Entities: []string{"example.com", "other.example"}, SharedValue: "192.0.2.10"},
				{ID: "historical", Type: CorrelationSharedHistoricalIPAddress, Entities: []string{"example.com", "other.example"}, SharedValue: "192.0.2.10"},
			},
		},
		{
			name: "live TLS and CT record",
			correlations: []Correlation{
				{ID: "tls", Type: CorrelationSharedTLSCertificateFingerprint, Entities: []string{"example.com", "other.example"}, SharedValue: strings.Repeat("a", 64)},
				{ID: "ct", Type: CorrelationSharedCTCertificateRecord, Entities: []string{"example.com", "other.example"}, SharedValue: "crt.sh#77"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			results, err := engine.Discover(test.correlations, "example.com")
			if err != nil {
				t.Fatalf("Discover() error = %v", err)
			}
			if len(results) != 0 {
				t.Fatalf("same underlying evidence dimension produced a discovery: %#v", results)
			}
		})
	}
}

func TestDiscoveryValidationRejectsUnsupportedConfidence(t *testing.T) {
	discovery := Discovery{
		ID: "discovery:test", Type: DiscoveryConvergentInfrastructure,
		Entities: []string{"example.com", "other.example"},
		SignalTypes: []CorrelationType{CorrelationSharedIPAddress, CorrelationSharedTLSCertificateFingerprint},
		CorrelationIDs: []string{"ip", "tls"}, SharedValues: []string{"192.0.2.10", strings.Repeat("a", 64)},
		SignalDiversity: 2, Confidence: "MODERATE",
		Statement: "Cross-dimension lead.", WhyItMatters: "Needs investigation.",
		AlternativeExplanations: "Shared providers may explain the overlap.",
		Verification:            []string{"Compare independent evidence."},
	}
	if err := discovery.Validate(); err == nil {
		t.Fatal("expected uncalibrated confidence to be rejected")
	}
}
