package intelligence

import (
	"strings"
	"testing"
)

func TestBuildIntelligenceGapsSurfacesEvidenceBoundQuestions(t *testing.T) {
	report := IntelligenceReport{
		Target: "target.example",
		Discoveries: []Discovery{{
			ID: "discovery:convergent", Entities: []string{"target.example", "peer.example"},
			CorrelationIDs:          []string{"corr-ip", "corr-tls"},
			AlternativeExplanations: "Shared hosting or centrally managed certificates.",
		}},
		DiscoveryPaths: []DiscoveryPath{{
			ID: "path:one", Entities: []string{"target.example", "pivot.example", "neighbor.example"},
			CorrelationIDs:          []string{"corr-ip", "corr-cert"},
			AlternativeExplanations: "The two hops may reflect unrelated shared services.",
		}},
		DiscoveryPivots: []DiscoveryPivot{{
			ID: "pivot:one", Pivot: "pivot.example", PathIDs: []string{"path:one"},
			AlternativeExplanations: "The pivot may be a shared provider.",
		}},
		VerificationAssessments: []VerificationAssessment{{
			HypothesisID: "hypothesis:one", Status: VerificationMixed,
			SupportingEvidenceIDs:    []string{"independent-support"},
			ContradictingEvidenceIDs: []string{"independent-conflict"},
			ExcludedEvidenceIDs:      []string{"original"},
			Limitations:              "Assessment is not proof.",
		}},
		Correlations: []Correlation{{
			ID: "corr-ip", Entities: []string{"target.example", "pivot.example"},
			EvidenceIDs: []string{"dns-target", "dns-pivot"},
		}, {
			ID: "corr-cert", Entities: []string{"pivot.example", "neighbor.example"},
			EvidenceIDs: []string{"tls-pivot", "tls-neighbor"},
		}},
	}
	gaps, err := BuildIntelligenceGaps(report)
	if err != nil {
		t.Fatalf("BuildIntelligenceGaps() error = %v", err)
	}
	if len(gaps) != 4 {
		t.Fatalf("got %d gaps, want 4", len(gaps))
	}
	kinds := map[string]bool{}
	for _, gap := range gaps {
		kinds[gap.Kind] = true
		if err := gap.Validate(); err != nil {
			t.Errorf("gap %q invalid: %v", gap.ID, err)
		}
		if len(gap.References) == 0 {
			t.Errorf("gap %q has no references", gap.ID)
		}
	}
	for _, kind := range []string{"INDEPENDENT_CONFIRMATION", "UNOBSERVED_DIRECT_EDGE", "PIVOT_ROLE_AMBIGUITY", "EVIDENCE_CONFLICT"} {
		if !kinds[kind] {
			t.Errorf("missing gap kind %q", kind)
		}
	}
	if !strings.Contains(gaps[0].ID, "gap:") {
		t.Fatalf("unexpected stable gap ID: %q", gaps[0].ID)
	}
	again, err := BuildIntelligenceGaps(report)
	if err != nil {
		t.Fatal(err)
	}
	for i := range gaps {
		if gaps[i].ID != again[i].ID {
			t.Fatalf("gap ordering is not deterministic at %d", i)
		}
	}
}

func TestBuildIntelligenceGapsDoesNotInventDirectEdgeGapWhenDirectCorrelationExists(t *testing.T) {
	report := IntelligenceReport{
		Target: "target.example",
		DiscoveryPaths: []DiscoveryPath{{
			ID: "path:one", Entities: []string{"target.example", "pivot.example", "neighbor.example"},
			CorrelationIDs:          []string{"hop-a", "hop-b"},
			AlternativeExplanations: "Shared infrastructure.",
		}},
		Correlations: []Correlation{{
			ID: "direct", Entities: []string{"target.example", "neighbor.example"},
			EvidenceIDs: []string{"direct-evidence"},
		}},
	}
	gaps, err := BuildIntelligenceGaps(report)
	if err != nil {
		t.Fatal(err)
	}
	if len(gaps) != 0 {
		t.Fatalf("expected no gaps, got %#v", gaps)
	}
}

func TestBuildIntelligenceGapsEmptyReport(t *testing.T) {
	gaps, err := BuildIntelligenceGaps(IntelligenceReport{Target: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if gaps == nil || len(gaps) != 0 {
		t.Fatalf("expected a non-nil empty gap list, got %#v", gaps)
	}
}
