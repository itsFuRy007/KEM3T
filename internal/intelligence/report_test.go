package intelligence

import (
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
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
	report, err := engine.Build("example.com", nil, registry)
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
