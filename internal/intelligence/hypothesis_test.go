package intelligence

import (
	"strings"
	"testing"
)

func TestHypothesisEngineGeneratesSharedInfrastructureHypothesis(t *testing.T) {
	engine := &HypothesisEngine{}

	input := []Correlation{
		{
			ID:          "shared-ip:192.0.2.10",
			Type:        CorrelationSharedIPAddress,
			Entities:    []string{"b.example.com", "a.example.com"},
			SharedValue: "192.0.2.10",
			EvidenceIDs: []string{"ev-b", "ev-a", "ev-a"},
		},
	}

	results, err := engine.Generate(input)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected 1 hypothesis, got %d", len(results))
	}

	got := results[0]
	if err := got.Validate(); err != nil {
		t.Fatalf("generated hypothesis is invalid: %v", err)
	}
	if got.Confidence != HypothesisConfidenceLow {
		t.Fatalf("expected conservative LOW confidence, got %q", got.Confidence)
	}
	if len(got.SupportingIDs) != 2 {
		t.Fatalf("expected deduplicated evidence IDs, got %#v", got.SupportingIDs)
	}
	if got.SupportingIDs[0] != "ev-a" || got.SupportingIDs[1] != "ev-b" {
		t.Fatalf("supporting IDs are not sorted: %#v", got.SupportingIDs)
	}
	if !strings.Contains(got.Statement, "192.0.2.10") {
		t.Fatalf("statement should identify the shared IP: %q", got.Statement)
	}
	if len(got.Verification) == 0 {
		t.Fatal("expected verification steps")
	}
}

func TestHypothesisEngineReturnsDeterministicOrder(t *testing.T) {
	engine := &HypothesisEngine{}

	input := []Correlation{
		{
			ID:          "shared-ip:192.0.2.20",
			Type:        CorrelationSharedIPAddress,
			Entities:    []string{"b.example.com", "c.example.com"},
			SharedValue: "192.0.2.20",
			EvidenceIDs: []string{"ev-b", "ev-c"},
		},
		{
			ID:          "shared-ip:192.0.2.10",
			Type:        CorrelationSharedIPAddress,
			Entities:    []string{"a.example.com", "b.example.com"},
			SharedValue: "192.0.2.10",
			EvidenceIDs: []string{"ev-a", "ev-b"},
		},
	}

	results, err := engine.Generate(input)
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("expected 2 hypotheses, got %d", len(results))
	}
	if results[0].ID > results[1].ID {
		t.Fatalf("hypotheses are not sorted: %q before %q", results[0].ID, results[1].ID)
	}
}

func TestHypothesisEngineRejectsMissingEvidence(t *testing.T) {
	engine := &HypothesisEngine{}

	_, err := engine.Generate([]Correlation{
		{
			ID:          "shared-ip:192.0.2.10",
			Type:        CorrelationSharedIPAddress,
			Entities:    []string{"a.example.com", "b.example.com"},
			SharedValue: "192.0.2.10",
		},
	})
	if err == nil {
		t.Fatal("expected error when evidence IDs are missing")
	}
}

func TestHypothesisEngineRejectsUnsupportedCorrelationType(t *testing.T) {
	engine := &HypothesisEngine{}

	_, err := engine.Generate([]Correlation{
		{
			ID:          "unknown:1",
			Type:        CorrelationType("UNKNOWN"),
			Entities:    []string{"a.example.com", "b.example.com"},
			SharedValue: "value",
			EvidenceIDs: []string{"ev-a"},
		},
	})
	if err == nil {
		t.Fatal("expected error for unsupported correlation type")
	}
}

func TestHypothesisValidateRejectsMissingAlternative(t *testing.T) {
	hypothesis := Hypothesis{
		ID:              "hypothesis:test",
		Title:           "Test hypothesis",
		Statement:       "A testable statement.",
		Confidence:      HypothesisConfidenceLow,
		SupportingIDs:   []string{"ev-a"},
		SupportingFacts: []string{"A fact."},
		Limitations:     "A limitation.",
		Verification:    []string{"Verify the evidence."},
	}

	if err := hypothesis.Validate(); err == nil {
		t.Fatal("expected validation error for missing alternative explanation")
	}
}
