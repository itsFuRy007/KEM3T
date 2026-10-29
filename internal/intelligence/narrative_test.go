package intelligence

import (
	"strings"
	"testing"
)

func TestBuildResearchNarrativeTraceability(t *testing.T) {
	report := IntelligenceReport{
		Target: "example.com",
		Correlations: []Correlation{{
			ID: "shared-ip:192.0.2.10", Type: CorrelationSharedIPAddress,
			Entities: []string{"example.com", "api.example.net"}, SharedValue: "192.0.2.10",
			EvidenceIDs: []string{"evidence-a", "evidence-b"}, ObservationIDs: []string{"obs-a"},
			Confidence: "HIGH", ConfidenceScope: "OBSERVED_SHARED_ADDRESS",
			Explanation: "Two entities were observed on the same address.",
			Limitations: "Shared hosting can explain this observation.",
		}},
		Discoveries: []Discovery{{
			ID: "discovery:one", Type: DiscoveryConvergentInfrastructure,
			Statement: "Two entities converge across infrastructure dimensions.", Confidence: "MODERATE",
			CorrelationIDs: []string{"shared-ip:192.0.2.10"}, AlternativeExplanations: "Shared provider.",
			WhyItMatters: "Multiple dimensions merit review.", Verification: []string{"Check network ownership."},
		}},
		Hypotheses: []Hypothesis{{
			ID: "hypothesis:one", Title: "Potential shared infrastructure", Statement: "They may share infrastructure.",
			Confidence: HypothesisConfidenceLow, SupportingIDs: []string{"evidence-a"},
			SupportingFacts: []string{"Same address observed."}, Alternative: "Shared hosting.",
			Limitations: "No ownership inference.", Verification: []string{"Compare timestamps."},
		}},
		VerificationAssessments: []VerificationAssessment{{
			HypothesisID: "hypothesis:one", Status: VerificationMixed,
			SupportingEvidenceIDs: []string{"independent-a"}, SupportingFacts: []string{"Supports."},
			ContradictingEvidenceIDs: []string{"independent-b"}, ContradictingFacts: []string{"Contradicts."},
			ExcludedEvidenceIDs: []string{"evidence-a"}, Explanation: "Independent evidence conflicts.",
			Limitations: "Status is not a probability.",
		}},
	}
	narrative, err := BuildResearchNarrative(report)
	if err != nil { t.Fatalf("BuildResearchNarrative() error = %v", err) }
	if !strings.Contains(narrative.Summary, "example.com") { t.Fatalf("target missing from summary: %q", narrative.Summary) }
	if len(narrative.Signals) != 4 { t.Fatalf("signals = %d, want 4", len(narrative.Signals)) }
	var evidenceRef, mixedAssessment bool
	for _, signal := range narrative.Signals {
		for _, ref := range signal.References { if ref == "evidence:evidence-a" { evidenceRef = true } }
		if signal.Kind == "VERIFICATION_ASSESSMENT" && strings.Contains(signal.Summary, "MIXED") { mixedAssessment = true }
	}
	if !evidenceRef { t.Fatal("original evidence reference was not preserved") }
	if !mixedAssessment { t.Fatal("mixed verification status was not surfaced") }
	if len(narrative.NextSteps) != 3 { t.Fatalf("next steps = %d, want 3", len(narrative.NextSteps)) }
	for _, step := range narrative.NextSteps { if len(step.References) == 0 { t.Errorf("step %q has no references", step.ID) } }
	if err := narrative.Validate(); err != nil { t.Fatalf("Validate() error = %v", err) }
}

func TestBuildResearchNarrativeEmptyReport(t *testing.T) {
	narrative, err := BuildResearchNarrative(IntelligenceReport{Target: "example.com"})
	if err != nil { t.Fatalf("BuildResearchNarrative() error = %v", err) }
	if !strings.Contains(narrative.Summary, "No evidence-backed signals") { t.Fatalf("unexpected summary: %q", narrative.Summary) }
	if narrative.Signals == nil || narrative.NextSteps == nil { t.Fatal("empty collections must be arrays") }
}

func TestResearchNarrativeRejectsUnlinkedSignal(t *testing.T) {
	err := (ResearchNarrative{
		Summary: "A summary.",
		Signals: []NarrativeSignal{{ID: "signal", Kind: "TEST", Summary: "Unlinked signal."}},
		NextSteps: []NarrativeNextStep{},
	}).Validate()
	if err == nil { t.Fatal("expected unlinked signal to be rejected") }
}
