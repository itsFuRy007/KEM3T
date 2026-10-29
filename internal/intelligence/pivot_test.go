package intelligence

import "testing"

func TestDiscoveryEngineSurfacesRecurringPivot(t *testing.T) {
	engine := &DiscoveryEngine{}
	paths := []DiscoveryPath{
		{
			ID: "path-1", Type: DiscoveryConvergentInfrastructure,
			Entities: []string{"target.example", "pivot.example", "neighbor-a.example"},
			CorrelationIDs: []string{"ip-1", "tls-1"},
			SignalTypes: []CorrelationType{CorrelationSharedIPAddress, CorrelationSharedTLSCertificateFingerprint},
			SignalDiversity: 2, Confidence: "LOW", Statement: "path", WhyItMatters: "pivot", AlternativeExplanations: "shared service",
			Verification: []string{"inspect evidence"},
		},
		{
			ID: "path-2", Type: DiscoveryConvergentInfrastructure,
			Entities: []string{"target.example", "pivot.example", "neighbor-b.example"},
			CorrelationIDs: []string{"hist-1", "ct-1"},
			SignalTypes: []CorrelationType{CorrelationSharedHistoricalIPAddress, CorrelationSharedCTCertificateRecord},
			SignalDiversity: 2, Confidence: "LOW", Statement: "path", WhyItMatters: "pivot", AlternativeExplanations: "shared service",
			Verification: []string{"inspect evidence"},
		},
	}

	results, err := engine.DiscoverPivots(paths, "target.example")
	if err != nil { t.Fatalf("DiscoverPivots() error = %v", err) }
	if len(results) != 1 { t.Fatalf("DiscoverPivots() returned %d pivots, want 1", len(results)) }
	got := results[0]
	if got.Pivot != "pivot.example" { t.Fatalf("pivot = %q, want pivot.example", got.Pivot) }
	if len(got.ConnectedEntities) != 2 { t.Fatalf("connected entities = %d, want 2", len(got.ConnectedEntities)) }
	if got.SignalDiversity != 4 { t.Fatalf("signal diversity = %d, want 4", got.SignalDiversity) }
	if got.Confidence != "LOW" { t.Fatalf("confidence = %q, want LOW", got.Confidence) }
	if err := got.Validate(); err != nil { t.Fatalf("Validate() error = %v", err) }
}

func TestDiscoveryEngineDoesNotPromoteSinglePathPivot(t *testing.T) {
	engine := &DiscoveryEngine{}
	paths := []DiscoveryPath{{
		ID: "path-1", Type: DiscoveryConvergentInfrastructure,
		Entities: []string{"target.example", "pivot.example", "neighbor.example"},
		CorrelationIDs: []string{"ip-1", "tls-1"},
		SignalTypes: []CorrelationType{CorrelationSharedIPAddress, CorrelationSharedTLSCertificateFingerprint},
		SignalDiversity: 2, Confidence: "LOW", Statement: "path", WhyItMatters: "pivot", AlternativeExplanations: "shared service",
		Verification: []string{"inspect evidence"},
	}}
	results, err := engine.DiscoverPivots(paths, "target.example")
	if err != nil { t.Fatalf("DiscoverPivots() error = %v", err) }
	if len(results) != 0 { t.Fatalf("DiscoverPivots() returned %d pivots, want 0", len(results)) }
}

func TestDiscoveryEngineRejectsMalformedPathBeforePivotAggregation(t *testing.T) {
	_, err := (&DiscoveryEngine{}).DiscoverPivots([]DiscoveryPath{{ID: "broken"}}, "target.example")
	if err == nil { t.Fatal("expected malformed path to be rejected") }
}
