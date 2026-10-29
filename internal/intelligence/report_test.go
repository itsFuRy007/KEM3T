package intelligence

import (
	"strings"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/events"
)

func TestReportEngineRejectsMissingTarget(t *testing.T) {
	engine := &ReportEngine{}

	_, err := engine.Build(" ", nil, nil)
	if err == nil {
		t.Fatal("expected error for missing target")
	}
}

func TestReportEngineRejectsMissingRegistry(t *testing.T) {
	engine := &ReportEngine{}

	_, err := engine.Build("example.com", nil, nil)
	if err == nil {
		t.Fatal("expected error for missing evidence registry")
	}
}

func TestReportEngineBuildsEmptyReport(t *testing.T) {
	registry := evidence.NewRegistry()
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("close evidence registry: %v", err)
		}
	})

	engine := &ReportEngine{}
	report, err := engine.Build("example.com", nil, registry)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if report.Target != "example.com" {
		t.Fatalf("unexpected target: %q", report.Target)
	}
	if report.Findings == nil {
		t.Fatal("expected findings to be an empty array, not nil")
	}
	if report.Correlations == nil {
		t.Fatal("expected correlations to be an empty array, not nil")
	}
	if report.Discoveries == nil {
		t.Fatal("expected discoveries to be an empty array, not nil")
	}
	if report.DiscoveryPaths == nil {
		t.Fatal("expected discovery paths to be an empty array, not nil")
	}
	if report.DiscoveryPivots == nil {
		t.Fatal("expected discovery pivots to be an empty array, not nil")
	}
	if report.Hypotheses == nil {
		t.Fatal("expected hypotheses to be an empty array, not nil")
	}
	if report.VerificationAssessments == nil {
		t.Fatal("expected verification assessments to be an empty array, not nil")
	}
	if report.PrioritizedFindings == nil {
		t.Fatal("expected prioritized findings to be an empty array, not nil")
	}
}

func TestReportEngineRejectsInvalidFinding(t *testing.T) {
	registry := evidence.NewRegistry()
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("close evidence registry: %v", err)
		}
	})

	engine := &ReportEngine{}
	_, err := engine.Build("example.com", []Finding{
		{Title: "Invalid finding"},
	}, registry)
	if err == nil {
		t.Fatal("expected error for invalid finding")
	}
}

func TestReportEngineBuildsCorrelationsAndHypotheses(t *testing.T) {
	registry := evidence.NewRegistry()
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("close evidence registry: %v", err)
		}
	})

	records := []evidence.Evidence{
		{
			ID:       "dns-address:a.example.com:192.0.2.50",
			EntityID: "a.example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.50",
		},
		{
			ID:       "dns-address:b.example.com:192.0.2.50",
			EntityID: "b.example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.50",
		},
	}

	for _, record := range records {
		if err := registry.AddEvidence(record); err != nil {
			t.Fatalf("AddEvidence(%q): %v", record.ID, err)
		}
	}

	observedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	observations := []evidence.Observation{
		{
			ID:         "observation:event-a",
			EvidenceID: records[0].ID,
			Source:     "integration-test",
			ObservedAt: observedAt,
			EventIDs:   []string{"event-a"},
		},
		{
			ID:         "observation:event-b",
			EvidenceID: records[1].ID,
			Source:     "integration-test",
			ObservedAt: observedAt.Add(time.Second),
			EventIDs:   []string{"event-b"},
		},
	}

	for _, observation := range observations {
		if err := registry.AddObservation(observation); err != nil {
			t.Fatalf("AddObservation(%q): %v", observation.ID, err)
		}
	}

	engine := &ReportEngine{}
	report, err := engine.Build("a.example.com", nil, registry)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}

	if len(report.Correlations) != 1 {
		t.Fatalf("expected 1 correlation, got %d", len(report.Correlations))
	}

	correlation := report.Correlations[0]
	if correlation.Type != CorrelationSharedIPAddress {
		t.Fatalf("unexpected correlation type: %q", correlation.Type)
	}
	if correlation.ConfidenceScope != "OBSERVED_SHARED_ADDRESS" {
		t.Fatalf("unexpected confidence scope: %q", correlation.ConfidenceScope)
	}
	if correlation.SharedValue != "192.0.2.50" {
		t.Fatalf("unexpected shared IP: %q", correlation.SharedValue)
	}
	if len(correlation.Entities) != 2 {
		t.Fatalf("expected 2 correlated entities, got %d", len(correlation.Entities))
	}
	if len(correlation.EvidenceIDs) != 2 {
		t.Fatalf("expected 2 supporting evidence IDs, got %d", len(correlation.EvidenceIDs))
	}
	if len(correlation.ObservationIDs) != 2 {
		t.Fatalf("expected 2 observation IDs, got %d", len(correlation.ObservationIDs))
	}

	if len(report.Hypotheses) != 1 {
		t.Fatalf("expected 1 hypothesis, got %d", len(report.Hypotheses))
	}

	hypothesis := report.Hypotheses[0]
	if hypothesis.Confidence != HypothesisConfidenceLow {
		t.Fatalf("expected LOW hypothesis confidence, got %q", hypothesis.Confidence)
	}
	if len(hypothesis.SupportingIDs) != 2 {
		t.Fatalf("expected 2 supporting evidence IDs, got %d", len(hypothesis.SupportingIDs))
	}
	if hypothesis.Alternative == "" {
		t.Fatal("expected alternative explanations")
	}
	if hypothesis.Limitations == "" {
		t.Fatal("expected hypothesis limitations")
	}
	if len(hypothesis.Verification) == 0 {
		t.Fatal("expected verification steps")
	}

	if len(report.PrioritizedFindings) != 0 {
		t.Fatalf("expected no prioritized findings, got %d", len(report.PrioritizedFindings))
	}
}

func TestReportEngineExcludesCorrelationsUnrelatedToTarget(t *testing.T) {
	registry := evidence.NewRegistry()
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("close evidence registry: %v", err)
		}
	})

	records := []evidence.Evidence{
		{ID: "dns-a", EntityID: "a.example.com", Type: evidence.TypeDNSAddress, Value: "192.0.2.10"},
		{ID: "dns-b", EntityID: "b.example.com", Type: evidence.TypeDNSAddress, Value: "192.0.2.10"},
		{ID: "dns-c", EntityID: "c.example.net", Type: evidence.TypeDNSAddress, Value: "192.0.2.20"},
		{ID: "dns-d", EntityID: "d.example.net", Type: evidence.TypeDNSAddress, Value: "192.0.2.20"},
	}
	for _, record := range records {
		if err := registry.AddEvidence(record); err != nil {
			t.Fatalf("AddEvidence(%q): %v", record.ID, err)
		}
	}

	report, err := (&ReportEngine{}).Build("A.EXAMPLE.COM.", nil, registry)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if len(report.Correlations) != 1 {
		t.Fatalf("expected only target-related correlation, got %d", len(report.Correlations))
	}
	if report.Correlations[0].SharedValue != "192.0.2.10" {
		t.Fatalf("unexpected unrelated correlation returned: %q", report.Correlations[0].SharedValue)
	}
	if report.Target != "a.example.com" {
		t.Fatalf("expected normalized report target, got %q", report.Target)
	}
}


func reportScopeFinding(id, target string) Finding {
	return Finding{
		Title:    "Observed asset " + target,
		Priority: PriorityInfo,
		Fact:     "Observed target " + target,
		Evidence: []events.Event{{
			ID: id, Type: events.EventSubdomainDiscovered,
			Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			Target: target, Source: "test",
		}},
	}
}

func TestReportEngineScopesFindingsToTargetAndSubdomains(t *testing.T) {
	registry := evidence.NewRegistry()
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("close evidence registry: %v", err)
		}
	})

	findings := []Finding{
		reportScopeFinding("root", "example.com"),
		reportScopeFinding("subdomain", "api.example.com"),
		reportScopeFinding("unrelated", "example.net"),
		reportScopeFinding("lookalike", "example.com.attacker.test"),
	}
	report, err := (&ReportEngine{}).Build("https://EXAMPLE.COM:443/path", findings, registry)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if report.Target != "example.com" {
		t.Fatalf("expected normalized host target, got %q", report.Target)
	}
	if len(report.Findings) != 2 {
		t.Fatalf("expected root and true subdomain findings only, got %d", len(report.Findings))
	}
	if len(report.PrioritizedFindings) != 2 {
		t.Fatalf("expected only scoped findings to be prioritized, got %d", len(report.PrioritizedFindings))
	}
	for _, finding := range report.Findings {
		if finding.Title == "Observed asset example.net" || finding.Title == "Observed asset example.com.attacker.test" {
			t.Errorf("unrelated finding leaked into report: %q", finding.Title)
		}
	}
}

func TestReportEngineRejectsMixedScopeAggregateFinding(t *testing.T) {
	registry := evidence.NewRegistry()
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("close evidence registry: %v", err)
		}
	})

	finding := reportScopeFinding("in-scope", "example.com")
	finding.Evidence = append(finding.Evidence, events.Event{
		ID: "out-of-scope", Type: events.EventSubdomainDiscovered,
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Target: "other.example.net", Source: "test",
	})
	_, err := (&ReportEngine{}).Build("example.com", []Finding{finding}, registry)
	if err == nil {
		t.Fatal("expected mixed-scope aggregate finding to be rejected")
	}
}


func TestReportEngineIncludesSharedTLSCertificateIntelligence(t *testing.T) {
	registry := evidence.NewRegistry()
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("close evidence registry: %v", err)
		}
	})

	fingerprint := "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	for _, record := range []evidence.Evidence{
		tlsEvidenceForTest(t, "tls-a", "a.example.com", fingerprint),
		tlsEvidenceForTest(t, "tls-b", "b.example.com", fingerprint),
	} {
		if err := registry.AddEvidence(record); err != nil {
			t.Fatalf("AddEvidence(%q): %v", record.ID, err)
		}
	}

	report, err := (&ReportEngine{}).Build("a.example.com", nil, registry)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if len(report.Correlations) != 1 {
		t.Fatalf("expected one target-related certificate correlation, got %d", len(report.Correlations))
	}
	if report.Correlations[0].Type != CorrelationSharedTLSCertificateFingerprint {
		t.Fatalf("unexpected correlation type: %q", report.Correlations[0].Type)
	}
	if len(report.Hypotheses) != 1 || !strings.Contains(report.Hypotheses[0].Title, "TLS certificate") {
		t.Fatalf("expected certificate-specific hypothesis in report, got %#v", report.Hypotheses)
	}
	if report.Hypotheses[0].Confidence != HypothesisConfidenceLow {
		t.Fatalf("expected conservative LOW confidence, got %q", report.Hypotheses[0].Confidence)
	}
}


// TestReportEngineIntegratesEvidenceCorrelationHypothesisAndVerification exercises
// the complete Phase 5 path and ensures original evidence cannot corroborate itself.
func TestReportEngineIntegratesEvidenceCorrelationHypothesisAndVerification(t *testing.T) {
	registry := evidence.NewRegistry()
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("close evidence registry: %v", err)
		}
	})

	records := []evidence.Evidence{
		{ID: "dns-a", EntityID: "a.example.com", Type: evidence.TypeDNSAddress, Value: "192.0.2.50"},
		{ID: "dns-b", EntityID: "b.example.com", Type: evidence.TypeDNSAddress, Value: "192.0.2.50"},
	}
	for _, record := range records {
		if err := registry.AddEvidence(record); err != nil {
			t.Fatalf("AddEvidence(%q): %v", record.ID, err)
		}
	}
	observedAt := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for i, record := range records {
		observation := evidence.Observation{
			ID: "observation-" + record.ID, EvidenceID: record.ID,
			Source: "dns-collector", ObservedAt: observedAt.Add(time.Duration(i) * time.Second),
			EventIDs: []string{"event-" + record.ID},
		}
		if err := registry.AddObservation(observation); err != nil {
			t.Fatalf("AddObservation(%q): %v", observation.ID, err)
		}
	}

	const hypothesisID = "hypothesis:shared-ip:192.0.2.50"
	report, err := (&ReportEngine{}).BuildWithVerification(
		"a.example.com", nil, registry,
		map[string][]VerificationEvidence{
			hypothesisID: {
				{ID: "dns-a", Fact: "Original DNS evidence repeated.", Relation: VerificationSupports, Independent: true},
				{ID: "independent-support", Fact: "An independently collected certificate signal links both hosts.", Relation: VerificationSupports, Independent: true},
				{ID: "independent-conflict", Fact: "Independent ownership records identify separate operators.", Relation: VerificationContradicts, Independent: true},
			},
		},
	)
	if err != nil {
		t.Fatalf("BuildWithVerification returned error: %v", err)
	}
	if len(report.Correlations) != 1 || len(report.Hypotheses) != 1 {
		t.Fatalf("expected one correlation and one hypothesis, got %d and %d", len(report.Correlations), len(report.Hypotheses))
	}
	if len(report.VerificationAssessments) != 1 {
		t.Fatalf("expected one verification assessment, got %d", len(report.VerificationAssessments))
	}
	assessment := report.VerificationAssessments[0]
	if assessment.HypothesisID != hypothesisID {
		t.Fatalf("assessment attached to wrong hypothesis: %q", assessment.HypothesisID)
	}
	if assessment.Status != VerificationMixed {
		t.Fatalf("expected conflicting independent evidence to yield MIXED, got %q", assessment.Status)
	}
	if len(assessment.ExcludedEvidenceIDs) != 1 || assessment.ExcludedEvidenceIDs[0] != "dns-a" {
		t.Fatalf("original evidence must be disclosed as excluded: %#v", assessment.ExcludedEvidenceIDs)
	}
	if len(assessment.SupportingEvidenceIDs) != 1 || assessment.SupportingEvidenceIDs[0] != "independent-support" {
		t.Fatalf("unexpected independent supporting evidence: %#v", assessment.SupportingEvidenceIDs)
	}
	if len(assessment.ContradictingEvidenceIDs) != 1 || assessment.ContradictingEvidenceIDs[0] != "independent-conflict" {
		t.Fatalf("unexpected independent contradicting evidence: %#v", assessment.ContradictingEvidenceIDs)
	}
	if report.Hypotheses[0].Confidence != HypothesisConfidenceLow {
		t.Fatalf("verification must not silently raise hypothesis confidence, got %q", report.Hypotheses[0].Confidence)
	}
}

// TestReportEngineRejectsVerificationForUnknownHypothesis prevents silent loss
// of verification records due to a typo or a hypothesis outside report scope.
func TestReportEngineRejectsVerificationForUnknownHypothesis(t *testing.T) {
	registry := evidence.NewRegistry()
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("close evidence registry: %v", err)
		}
	})

	_, err := (&ReportEngine{}).BuildWithVerification(
		"example.com", nil, registry,
		map[string][]VerificationEvidence{
			"hypothesis:typo": {{ID: "e1", Fact: "Fact.", Relation: VerificationSupports, Independent: true}},
		},
	)
	if err == nil {
		t.Fatal("expected unknown hypothesis verification to be rejected")
	}
}


func TestReportEngineBuildsMultiHopPathsAndRecurringPivots(t *testing.T) {
	registry := evidence.NewRegistry()
	t.Cleanup(func() {
		if err := registry.Close(); err != nil {
			t.Errorf("close evidence registry: %v", err)
		}
	})

	fingerprint := "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	records := []evidence.Evidence{
		{ID: "dns-target", EntityID: "target.example", Type: evidence.TypeDNSAddress, Value: "192.0.2.80"},
		{ID: "dns-pivot", EntityID: "pivot.example", Type: evidence.TypeDNSAddress, Value: "192.0.2.80"},
		tlsEvidenceForTest(t, "tls-pivot", "pivot.example", fingerprint),
		tlsEvidenceForTest(t, "tls-neighbor-a", "neighbor-a.example", fingerprint),
		tlsEvidenceForTest(t, "tls-neighbor-b", "neighbor-b.example", fingerprint),
	}
	for _, record := range records {
		if err := registry.AddEvidence(record); err != nil {
			t.Fatalf("AddEvidence(%q): %v", record.ID, err)
		}
	}

	report, err := (&ReportEngine{}).Build("target.example", nil, registry)
	if err != nil {
		t.Fatalf("Build returned error: %v", err)
	}
	if len(report.Correlations) != 1 || report.Correlations[0].Type != CorrelationSharedIPAddress {
		t.Fatalf("direct report correlations should remain target-scoped; got %#v", report.Correlations)
	}
	if len(report.DiscoveryPaths) != 2 {
		t.Fatalf("expected two target-to-neighbor paths through the pivot, got %d", len(report.DiscoveryPaths))
	}
	if len(report.DiscoveryPivots) != 1 {
		t.Fatalf("expected one recurring pivot, got %d", len(report.DiscoveryPivots))
	}
	pivot := report.DiscoveryPivots[0]
	if pivot.Pivot != "pivot.example" {
		t.Fatalf("unexpected pivot: %q", pivot.Pivot)
	}
	if len(pivot.PathIDs) != 2 || len(pivot.ConnectedEntities) != 2 {
		t.Fatalf("pivot must retain both supporting paths and neighbors: %#v", pivot)
	}
}
