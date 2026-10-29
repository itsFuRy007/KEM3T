package intelligence

import (
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
	if report.Hypotheses == nil {
		t.Fatal("expected hypotheses to be an empty array, not nil")
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
