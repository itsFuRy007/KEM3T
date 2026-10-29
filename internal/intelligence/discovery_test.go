package intelligence

import "testing"

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
	if err != nil { t.Fatalf("Discover() error = %v", err) }
	if len(results) != 1 { t.Fatalf("Discover() returned %d discoveries, want 1", len(results)) }
	got := results[0]
	if got.Type != DiscoveryConvergentInfrastructure { t.Fatalf("unexpected type %q", got.Type) }
	if got.SignalDiversity != 2 { t.Fatalf("signal diversity = %d, want 2", got.SignalDiversity) }
	if len(got.CorrelationIDs) != 2 { t.Fatalf("correlation IDs = %d, want 2", len(got.CorrelationIDs)) }
	if got.Confidence != "MODERATE" { t.Fatalf("confidence = %q, want MODERATE", got.Confidence) }
	if err := got.Validate(); err != nil { t.Fatalf("Validate() error = %v", err) }
}

func TestDiscoveryEngineDoesNotTreatSameDimensionAsConvergence(t *testing.T) {
	engine := &DiscoveryEngine{}
	correlations := []Correlation{
		{ID: "shared-ip:203.0.113.10", Type: CorrelationSharedIPAddress, Entities: []string{"example.com", "api.example.net"}, SharedValue: "203.0.113.10", EvidenceIDs: []string{"e1"}},
		{ID: "shared-ip:203.0.113.11", Type: CorrelationSharedIPAddress, Entities: []string{"example.com", "api.example.net"}, SharedValue: "203.0.113.11", EvidenceIDs: []string{"e2"}},
	}
	results, err := engine.Discover(correlations, "example.com")
	if err != nil { t.Fatalf("Discover() error = %v", err) }
	if len(results) != 0 { t.Fatalf("Discover() returned %d discoveries, want 0", len(results)) }
}

func TestDiscoveryEngineSurfacesTwoHopConvergentPath(t *testing.T) {
	engine := &DiscoveryEngine{}
	correlations := []Correlation{
		{ID: "shared-ip:203.0.113.10", Type: CorrelationSharedIPAddress, Entities: []string{"target.example", "pivot.example"}, SharedValue: "203.0.113.10", EvidenceIDs: []string{"e-ip"}},
		{ID: "shared-tls-cert:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", Type: CorrelationSharedTLSCertificateFingerprint, Entities: []string{"pivot.example", "neighbor.example"}, SharedValue: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", EvidenceIDs: []string{"e-tls"}},
	}

	results, err := engine.DiscoverPaths(correlations, "target.example")
	if err != nil { t.Fatalf("DiscoverPaths() error = %v", err) }
	if len(results) != 1 { t.Fatalf("DiscoverPaths() returned %d paths, want 1", len(results)) }
	got := results[0]
	if got.Entities[0] != "target.example" || got.Entities[1] != "pivot.example" || got.Entities[2] != "neighbor.example" {
		t.Fatalf("unexpected path entities: %#v", got.Entities)
	}
	if got.SignalDiversity != 2 || len(got.CorrelationIDs) != 2 {
		t.Fatalf("unexpected path signals: diversity=%d correlations=%d", got.SignalDiversity, len(got.CorrelationIDs))
	}
	if got.Confidence != "LOW" { t.Fatalf("path confidence = %q, want LOW", got.Confidence) }
	if err := got.Validate(); err != nil { t.Fatalf("Validate() error = %v", err) }
}

func TestDiscoveryEngineDoesNotPromoteSameDimensionPath(t *testing.T) {
	engine := &DiscoveryEngine{}
	correlations := []Correlation{
		{ID: "shared-ip:203.0.113.10", Type: CorrelationSharedIPAddress, Entities: []string{"target.example", "pivot.example"}, SharedValue: "203.0.113.10", EvidenceIDs: []string{"e1"}},
		{ID: "shared-ip:203.0.113.11", Type: CorrelationSharedIPAddress, Entities: []string{"pivot.example", "neighbor.example"}, SharedValue: "203.0.113.11", EvidenceIDs: []string{"e2"}},
	}
	results, err := engine.DiscoverPaths(correlations, "target.example")
	if err != nil { t.Fatalf("DiscoverPaths() error = %v", err) }
	if len(results) != 0 { t.Fatalf("DiscoverPaths() returned %d paths, want 0", len(results)) }
}
