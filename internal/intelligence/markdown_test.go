package intelligence

import (
	"strings"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

func sampleMarkdownReport() IntelligenceReport {
	return IntelligenceReport{
		Target: "example.com",
		Narrative: ResearchNarrative{
			Summary: "Two independent-looking signals deserve review.\nDo not treat this as proof.",
			Signals: []NarrativeSignal{
				{ID: "signal:b", Kind: "DISCOVERY", Summary: "A pivot was observed.", Confidence: "LOW", References: []string{"path:2"}},
				{ID: "signal:a", Kind: "CORRELATION", Summary: "A shared address was observed.", Confidence: "OBSERVED", References: []string{"evidence:1"}},
			},
			NextSteps: []NarrativeNextStep{{
				ID: "step:1", Action: "Verify the pivot independently.", Reason: "The path may be explained by shared hosting.",
				References: []string{"path:2", "evidence:1"},
			}},
			Limitations: []string{"No ownership conclusion is supported."},
		},
		Correlations: []Correlation{{
			ID: "correlation:1", Type: CorrelationSharedIPAddress, Entities: []string{"example.com", "api.example.net"},
			SharedValue: "203.0.113.10", EvidenceIDs: []string{"evidence:1"}, ObservationIDs: []string{"observation:1"},
			Confidence: "OBSERVED", ConfidenceScope: "OBSERVED_SHARED_ADDRESS",
			Explanation: "Both names resolved to the same address.", Limitations: "Shared hosting is a plausible alternative.",
		}},
		Discoveries: []Discovery{{
			ID: "discovery:1", Type: DiscoveryConvergentInfrastructure, Entities: []string{"example.com", "api.example.net"},
			SignalTypes: []CorrelationType{CorrelationSharedIPAddress, CorrelationSharedTLSCertificateFingerprint},
			CorrelationIDs: []string{"correlation:1"}, Confidence: "LOW", Statement: "Signals converge across dimensions.",
			WhyItMatters: "This is worth independent review.", AlternativeExplanations: "A shared provider may explain it.",
			Verification: []string{"Inspect the source records."},
		}},
		DiscoveryPaths: []DiscoveryPath{{
			ID: "path:2", Type: DiscoveryConvergentInfrastructure,
			Entities: []string{"example.com", "pivot.example.com", "other.example.net"},
			CorrelationIDs: []string{"correlation:1", "correlation:2"},
			SignalTypes: []CorrelationType{CorrelationSharedIPAddress, CorrelationSharedTLSCertificateFingerprint},
			SignalDiversity: 2, Confidence: "LOW", Statement: "A two-hop path reaches another host.",
			WhyItMatters: "The intermediate entity may be useful.", AlternativeExplanations: "A CDN may explain the path.",
			Verification: []string{"Inspect both hops."},
		}},
		DiscoveryPivots: []DiscoveryPivot{{
			ID: "pivot:1", Type: "DISCOVERY_PIVOT", Pivot: "pivot.example.com",
			ConnectedEntities: []string{"example.com", "other.example.net"}, PathIDs: []string{"path:2", "path:3"},
			SignalTypes: []CorrelationType{CorrelationSharedIPAddress, CorrelationSharedTLSCertificateFingerprint},
			SignalDiversity: 2, Confidence: "LOW", Statement: "The pivot recurs across paths.",
			WhyItMatters: "It may reveal a shared infrastructure hub.", AlternativeExplanations: "Shared hosting may explain it.",
			Verification: []string{"Check the pivot independently."},
		}},
		Hypotheses: []Hypothesis{{
			ID: "hypothesis:1", Title: "Potential shared infrastructure", Statement: "The entities may use a shared service.",
			Confidence: HypothesisConfidenceLow, SupportingIDs: []string{"evidence:1"}, SupportingFacts: []string{"Same IP observed."},
			Alternative: "CDN or shared hosting.", Limitations: "No ownership proof.", Verification: []string{"Check network ownership."},
		}},
		VerificationAssessments: []VerificationAssessment{{
			HypothesisID: "hypothesis:1", Status: VerificationMixed,
			SupportingEvidenceIDs: []string{"verification:yes"}, SupportingFacts: []string{"One independent source supports."},
			ContradictingEvidenceIDs: []string{"verification:no"}, ContradictingFacts: []string{"Another source conflicts."},
			ExcludedEvidenceIDs: []string{"verification:excluded"}, Explanation: "Evidence is mixed.", Limitations: "Further review is required.",
		}},
		IntelligenceGaps: []IntelligenceGap{{
			ID: "gap:1", Kind: "INDEPENDENT_CONFIRMATION", Subject: "example.com and api.example.net",
			Unknown: "Whether the relationship is meaningful.", WhyItMatters: "Avoid false attribution.",
			RequiredEvidence: []string{"Independent ownership records"}, SuggestedAction: "Seek an independent source.",
			AlternativeExplanations: "Shared hosting.", Priority: "HIGH", References: []string{"discovery:1"},
		}},
		PrioritizedFindings: []PrioritizedFinding{{
			Finding: Finding{Title: "Service observed", Priority: PriorityInfo, Fact: "A service responded.",
				Evidence: []events.Event{{ID: "event:1", Type: events.EventHTTPObserved, Timestamp: testTimestamp(), Target: "example.com", Source: "test", Data: map[string]string{"scheme": "https", "port": "443", "status_code": "200"}}}},
			Priority: PriorityInfo, Reason: "Observation only.",
		}},
		InvestigationPlan: InvestigationPlan{
			Target: "example.com", Revision: "revision", Summary: "1 active action.",
			Items: []InvestigationTask{{ID: "task:1", SourceID: "gap:1", SourceKind: "gap", Action: "Seek an independent source.",
				Rationale: "Resolve uncertainty.", Priority: 90, PriorityLabel: "HIGH", Status: TaskRecommended,
				References: []string{"gap:1"}, EvidenceIDs: []string{}}},
		},
	}
}

func testTimestamp() time.Time {
	return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
}

func TestRenderMarkdownReportIncludesResearcherSectionsAndTraceability(t *testing.T) {
	report := sampleMarkdownReport()
	got, err := RenderMarkdownReport(report)
	if err != nil { t.Fatalf("RenderMarkdownReport() error = %v", err) }
	for _, want := range []string{
		"# KEM3T Intelligence Dossier", "## Executive summary", "## Key signals",
		"## Direct correlations", "## Convergent discoveries", "## Multi-hop discovery paths",
		"## Recurring infrastructure pivots", "## Hypotheses", "## Verification assessments",
		"## Unresolved intelligence gaps", "## Prioritized findings", "## Researcher next steps",
		"## Adaptive investigation plan", "## Interpretation limits", "`evidence:1`",
		"`verification:yes`", "qualitative, not a probability",
	} {
		if !strings.Contains(got, want) { t.Errorf("Markdown report missing %q", want) }
	}
}

func TestRenderMarkdownReportEscapesUntrustedInlineText(t *testing.T) {
	report := IntelligenceReport{
		Target: "example.com",
		Narrative: ResearchNarrative{Summary: "Heading\n<script>alert(1)</script> *not bold*"},
	}
	got, err := RenderMarkdownReport(report)
	if err != nil { t.Fatal(err) }
	if strings.Contains(got, "<script>") { t.Fatal("raw HTML was not escaped") }
	if !strings.Contains(got, "&lt;script&gt;") || !strings.Contains(got, "\\*not bold\\*") {
		t.Fatalf("inline content was not safely escaped: %s", got)
	}
}

func TestRenderMarkdownReportIsDeterministicAndDoesNotMutateInput(t *testing.T) {
	report := sampleMarkdownReport()
	firstID := report.Narrative.Signals[0].ID
	first, err := RenderMarkdownReport(report)
	if err != nil { t.Fatal(err) }
	second, err := RenderMarkdownReport(report)
	if err != nil { t.Fatal(err) }
	if first != second { t.Fatal("Markdown rendering is not deterministic") }
	if report.Narrative.Signals[0].ID != firstID { t.Fatal("renderer mutated report slices") }
}

func TestRenderMarkdownReportRejectsMissingTarget(t *testing.T) {
	if _, err := RenderMarkdownReport(IntelligenceReport{}); err == nil {
		t.Fatal("expected missing target to be rejected")
	}
}
