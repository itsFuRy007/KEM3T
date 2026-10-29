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


func verificationTestHypothesis(t *testing.T) Hypothesis {
	t.Helper()
	results, err := (&HypothesisEngine{}).Generate([]Correlation{{
		ID: "shared-ip:192.0.2.10", Type: CorrelationSharedIPAddress,
		Entities: []string{"a.example.com", "b.example.com"},
		SharedValue: "192.0.2.10", EvidenceIDs: []string{"ev-original"},
	}})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	return results[0]
}

func TestHypothesisAssessmentPreservesContradictoryEvidence(t *testing.T) {
	hypothesis := verificationTestHypothesis(t)
	engine := &HypothesisEngine{}
	assessment, err := engine.Assess(hypothesis, []VerificationEvidence{
		{ID: "verify-z", Fact: "Independent certificate evidence links both names.", Relation: VerificationSupports, Independent: true},
		{ID: "verify-a", Fact: "Independent ownership records identify unrelated operators.", Relation: VerificationContradicts, Independent: true},
	})
	if err != nil {
		t.Fatalf("Assess returned error: %v", err)
	}
	if assessment.Status != VerificationMixed {
		t.Fatalf("expected MIXED status, got %q", assessment.Status)
	}
	if len(assessment.SupportingEvidenceIDs) != 1 || assessment.SupportingEvidenceIDs[0] != "verify-z" {
		t.Fatalf("unexpected supporting IDs: %#v", assessment.SupportingEvidenceIDs)
	}
	if len(assessment.ContradictingEvidenceIDs) != 1 || assessment.ContradictingEvidenceIDs[0] != "verify-a" {
		t.Fatalf("unexpected contradicting IDs: %#v", assessment.ContradictingEvidenceIDs)
	}
	if assessment.SupportingFacts[0] != "Independent certificate evidence links both names." {
		t.Fatalf("supporting fact lost its evidence pairing: %#v", assessment.SupportingFacts)
	}
	if assessment.ContradictingFacts[0] != "Independent ownership records identify unrelated operators." {
		t.Fatalf("contradicting fact lost its evidence pairing: %#v", assessment.ContradictingFacts)
	}
	if hypothesis.Confidence != HypothesisConfidenceLow {
		t.Fatalf("assessment must not silently change hypothesis confidence, got %q", hypothesis.Confidence)
	}
}

func TestHypothesisAssessmentExcludesReusedAndNonIndependentEvidence(t *testing.T) {
	hypothesis := verificationTestHypothesis(t)
	assessment, err := (&HypothesisEngine{}).Assess(hypothesis, []VerificationEvidence{
		{ID: "ev-original", Fact: "Original evidence repeated.", Relation: VerificationSupports, Independent: true},
		{ID: "verify-dependent", Fact: "A repeated interpretation.", Relation: VerificationSupports, Independent: false},
	})
	if err != nil {
		t.Fatalf("Assess returned error: %v", err)
	}
	if assessment.Status != VerificationInconclusive {
		t.Fatalf("expected INCONCLUSIVE status, got %q", assessment.Status)
	}
	if len(assessment.ExcludedEvidenceIDs) != 2 {
		t.Fatalf("expected reused and non-independent evidence to be disclosed, got %#v", assessment.ExcludedEvidenceIDs)
	}
	if len(assessment.SupportingEvidenceIDs) != 0 || len(assessment.ContradictingEvidenceIDs) != 0 {
		t.Fatalf("excluded evidence affected assessment: %#v", assessment)
	}
}

func TestHypothesisAssessmentStatuses(t *testing.T) {
	hypothesis := verificationTestHypothesis(t)
	engine := &HypothesisEngine{}
	cases := []struct {
		name string
		evidence []VerificationEvidence
		want VerificationStatus
	}{
		{name: "no evidence", want: VerificationUnverified},
		{name: "support", evidence: []VerificationEvidence{{ID: "support", Fact: "Independent support.", Relation: VerificationSupports, Independent: true}}, want: VerificationSupported},
		{name: "contradiction", evidence: []VerificationEvidence{{ID: "contradiction", Fact: "Independent contradiction.", Relation: VerificationContradicts, Independent: true}}, want: VerificationContradicted},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assessment, err := engine.Assess(hypothesis, tc.evidence)
			if err != nil {
				t.Fatalf("Assess returned error: %v", err)
			}
			if assessment.Status != tc.want {
				t.Fatalf("status = %q, want %q", assessment.Status, tc.want)
			}
		})
	}
}

func TestHypothesisAssessmentRejectsDuplicateEvidenceIDs(t *testing.T) {
	hypothesis := verificationTestHypothesis(t)
	_, err := (&HypothesisEngine{}).Assess(hypothesis, []VerificationEvidence{
		{ID: "duplicate", Fact: "Fact one.", Relation: VerificationSupports, Independent: true},
		{ID: " duplicate ", Fact: "Fact two.", Relation: VerificationContradicts, Independent: true},
	})
	if err == nil {
		t.Fatal("expected duplicate verification evidence IDs to be rejected")
	}
}


func TestHypothesisEngineGeneratesSharedTLSCertificateHypothesis(t *testing.T) {
	fingerprint := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	results, err := (&HypothesisEngine{}).Generate([]Correlation{{
		ID: "shared-tls-cert:" + fingerprint,
		Type: CorrelationSharedTLSCertificateFingerprint,
		Entities: []string{"a.example.com", "b.example.com"},
		SharedValue: fingerprint,
		EvidenceIDs: []string{"tls-a", "tls-b"},
	}})
	if err != nil {
		t.Fatalf("Generate returned error: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("expected one hypothesis, got %d", len(results))
	}
	got := results[0]
	if got.Confidence != HypothesisConfidenceLow {
		t.Fatalf("shared certificate hypothesis should remain LOW confidence, got %q", got.Confidence)
	}
	if !strings.Contains(got.Title, "TLS certificate") || !strings.Contains(got.Statement, fingerprint) {
		t.Fatalf("unexpected TLS hypothesis: %#v", got)
	}
	if !strings.Contains(got.Alternative, "wildcard") {
		t.Fatalf("expected alternative explanation for shared/wildcard certificates, got %q", got.Alternative)
	}
	if len(got.Verification) == 0 || !strings.Contains(got.Verification[1], "independent") {
		t.Fatalf("expected independent verification guidance, got %#v", got.Verification)
	}
}
