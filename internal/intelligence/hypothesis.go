package intelligence

import (
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strings"
)

// HypothesisConfidence expresses the strength of support for a hypothesis.
// It is not a probability that the hypothesis is true.
type HypothesisConfidence string

const (
	HypothesisConfidenceLow      HypothesisConfidence = "LOW"
	HypothesisConfidenceModerate HypothesisConfidence = "MODERATE"
	HypothesisConfidenceHigh     HypothesisConfidence = "HIGH"
)

// Hypothesis represents a testable interpretation of correlated evidence.
type Hypothesis struct {
	ID              string               `json:"id"`
	Title           string               `json:"title"`
	Statement       string               `json:"statement"`
	Confidence      HypothesisConfidence `json:"confidence"`
	SupportingIDs   []string             `json:"supporting_ids"`
	SupportingFacts []string             `json:"supporting_facts"`
	Alternative     string               `json:"alternative_explanations"`
	Limitations     string               `json:"limitations"`
	Verification    []string             `json:"verification_steps"`
}

// Validate checks whether a hypothesis is complete.
func (h Hypothesis) Validate() error {
	if strings.TrimSpace(h.ID) == "" {
		return fmt.Errorf("hypothesis ID is required")
	}
	if strings.TrimSpace(h.Title) == "" {
		return fmt.Errorf("hypothesis title is required")
	}
	if strings.TrimSpace(h.Statement) == "" {
		return fmt.Errorf("hypothesis statement is required")
	}

	switch h.Confidence {
	case HypothesisConfidenceLow,
		HypothesisConfidenceModerate,
		HypothesisConfidenceHigh:
	default:
		return fmt.Errorf("hypothesis confidence is invalid")
	}

	if len(h.SupportingIDs) == 0 {
		return fmt.Errorf("hypothesis must reference supporting evidence")
	}
	if len(h.SupportingFacts) == 0 {
		return fmt.Errorf("hypothesis must include supporting facts")
	}
	if strings.TrimSpace(h.Alternative) == "" {
		return fmt.Errorf("alternative explanations are required")
	}
	if strings.TrimSpace(h.Limitations) == "" {
		return fmt.Errorf("hypothesis limitations are required")
	}
	if len(h.Verification) == 0 {
		return fmt.Errorf("verification steps are required")
	}

	return nil
}

// HypothesisEngine creates testable hypotheses from correlations.
type HypothesisEngine struct{}

// Generate creates hypotheses from supported correlation types.
// Shared IP addresses produce low-confidence hypotheses because shared
// hosting, CDNs, and other infrastructure can explain the same observation.
func (e *HypothesisEngine) Generate(
	correlations []Correlation,
) ([]Hypothesis, error) {
	results := make([]Hypothesis, 0)
	seenCorrelationIDs := make(map[string]struct{}, len(correlations))

	for _, correlation := range correlations {
		if strings.TrimSpace(correlation.ID) == "" {
			return nil, fmt.Errorf("correlation ID is required")
		}
		correlationID := strings.TrimSpace(correlation.ID)
		if _, exists := seenCorrelationIDs[correlationID]; exists {
			return nil, fmt.Errorf("duplicate correlation ID %q", correlationID)
		}
		seenCorrelationIDs[correlationID] = struct{}{}
		if strings.TrimSpace(correlation.SharedValue) == "" {
			return nil, fmt.Errorf(
				"correlation %q has no shared value",
				correlation.ID,
			)
		}
		if len(correlation.Entities) < 2 {
			return nil, fmt.Errorf(
				"correlation %q must reference at least two entities",
				correlation.ID,
			)
		}
		if len(correlation.EvidenceIDs) == 0 {
			return nil, fmt.Errorf(
				"correlation %q has no supporting evidence IDs",
				correlation.ID,
			)
		}

		switch correlation.Type {
		case CorrelationSharedIPAddress, CorrelationSharedTLSCertificateFingerprint:
			if err := validateHypothesisCorrelation(correlation); err != nil {
				return nil, fmt.Errorf("invalid correlation %q: %w", correlation.ID, err)
			}
			entities := append([]string(nil), correlation.Entities...)
			for i := range entities {
				entities[i] = strings.ToLower(strings.TrimSpace(entities[i]))
				if entities[i] == "" {
					return nil, fmt.Errorf(
						"correlation %q contains an empty entity",
						correlation.ID,
					)
				}
			}
			sort.Strings(entities)
			entities = uniqueStrings(entities)

			if len(entities) < 2 {
				return nil, fmt.Errorf(
					"correlation %q must contain at least two distinct entities",
					correlation.ID,
				)
			}

			evidenceIDs := append([]string(nil), correlation.EvidenceIDs...)
			for i := range evidenceIDs {
				evidenceIDs[i] = strings.TrimSpace(evidenceIDs[i])
				if evidenceIDs[i] == "" {
					return nil, fmt.Errorf(
						"correlation %q contains an empty evidence ID",
						correlation.ID,
					)
				}
			}
			sort.Strings(evidenceIDs)
			evidenceIDs = uniqueStrings(evidenceIDs)

			title := "Potential shared infrastructure"
			statement := fmt.Sprintf(
				"The entities %s may share or use the same network infrastructure because they were observed resolving to %s.",
				strings.Join(entities, ", "), correlation.SharedValue,
			)
			supportingFact := fmt.Sprintf(
				"%d distinct entities were associated with IP address %s.",
				len(entities), correlation.SharedValue,
			)
			alternative := "The address may belong to a CDN, reverse proxy, shared hosting provider, cloud platform, or other shared service."
			limitations := "A shared IP address alone does not prove common ownership, control, a direct relationship, or a security weakness. Confidence is qualitative and is not a probability."
			verification := []string{
				"Collect timestamped DNS observations for each entity and compare answer sets across at least two collection times.",
				"Seek an independent signal, such as certificate names or fingerprints, that links the entities; retain the supporting evidence IDs and collection timestamps.",
				"Check whether the address belongs to shared hosting, a CDN, or a reverse proxy; if so, do not infer common ownership from the address alone.",
				"Keep this hypothesis at LOW confidence unless independent evidence supports a more specific relationship, and record contradictory observations.",
			}
			if correlation.Type == CorrelationSharedTLSCertificateFingerprint {
				title = "Potential shared TLS certificate deployment"
				statement = fmt.Sprintf(
					"The entities %s were observed presenting the same TLS certificate SHA-256 fingerprint (%s); this may reflect a shared or centrally managed certificate deployment.",
					strings.Join(entities, ", "), correlation.SharedValue,
				)
				supportingFact = fmt.Sprintf(
					"%d distinct entities presented the same TLS certificate SHA-256 fingerprint %s.",
					len(entities), correlation.SharedValue,
				)
				alternative = "The same wildcard or centrally managed certificate may be deployed across unrelated services, a hosting provider may manage certificates for customers, or endpoints may share a TLS termination layer."
				limitations = "A matching certificate fingerprint proves only that the same certificate was observed on these endpoints. It does not prove common ownership, a direct relationship, or a vulnerability. Confidence is qualitative and is not a probability."
				verification = []string{
					"Compare the certificate subject, SANs, issuer, validity period, and collection timestamps while retaining evidence references.",
					"Seek an independent signal such as DNS history, network ownership context, or a verified organizational record; do not count the same fingerprint twice as corroboration.",
					"Check for wildcard certificates, shared hosting, centralized TLS termination, or managed certificate deployment before inferring a relationship.",
					"Keep the hypothesis at LOW confidence unless independent evidence supports a more specific relationship, and record contradictory observations.",
				}
			}
			hypothesis := Hypothesis{
				ID: "hypothesis:" + correlation.ID, Title: title, Statement: statement,
				Confidence: HypothesisConfidenceLow, SupportingIDs: evidenceIDs,
				SupportingFacts: []string{supportingFact}, Alternative: alternative,
				Limitations: limitations, Verification: verification,
			}

			if err := hypothesis.Validate(); err != nil {
				return nil, fmt.Errorf(
					"validate hypothesis for correlation %q: %w",
					correlation.ID,
					err,
				)
			}

			results = append(results, hypothesis)

		default:
			return nil, fmt.Errorf(
				"unsupported correlation type %q",
				correlation.Type,
			)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].ID < results[j].ID
	})

	return results, nil
}


// validateHypothesisCorrelation prevents malformed correlation objects from
// being promoted into apparently authoritative intelligence.
func validateHypothesisCorrelation(correlation Correlation) error {
	expectedScope := "OBSERVED_SHARED_ADDRESS"
	switch correlation.Type {
	case CorrelationSharedIPAddress:
		ip := net.ParseIP(strings.TrimSpace(correlation.SharedValue))
		if ip == nil || ip.String() != strings.TrimSpace(correlation.SharedValue) {
			return fmt.Errorf("shared IP address must be valid and canonical")
		}
	case CorrelationSharedTLSCertificateFingerprint:
		expectedScope = "OBSERVED_SHARED_CERTIFICATE_FINGERPRINT"
		fingerprint := strings.TrimSpace(correlation.SharedValue)
		if len(fingerprint) != 64 {
			return fmt.Errorf("TLS certificate fingerprint must contain 64 hexadecimal characters")
		}
		if _, err := hex.DecodeString(fingerprint); err != nil || strings.ToLower(fingerprint) != fingerprint {
			return fmt.Errorf("TLS certificate fingerprint must be lowercase hexadecimal")
		}
	}
	if correlation.ConfidenceScope != expectedScope {
		return fmt.Errorf("confidence scope %q does not match correlation type", correlation.ConfidenceScope)
	}
	seenEvidence := make(map[string]struct{}, len(correlation.EvidenceIDs))
	for _, rawID := range correlation.EvidenceIDs {
		id := strings.TrimSpace(rawID)
		if id == "" {
			return fmt.Errorf("supporting evidence IDs must not be empty")
		}
		if _, exists := seenEvidence[id]; exists {
			return fmt.Errorf("duplicate supporting evidence ID %q", id)
		}
		seenEvidence[id] = struct{}{}
	}
	return nil
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return values
	}

	result := make([]string, 0, len(values))
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}


// VerificationRelation records whether an independently collected fact supports
// or contradicts a hypothesis. The engine never infers this relation itself.
type VerificationRelation string

const (
	VerificationSupports     VerificationRelation = "SUPPORTS"
	VerificationContradicts  VerificationRelation = "CONTRADICTS"
)

// VerificationStatus is an evidence assessment, not a probability or a verdict
// about ownership, compromise, or vulnerability.
type VerificationStatus string

const (
	VerificationUnverified   VerificationStatus = "UNVERIFIED"
	VerificationInconclusive VerificationStatus = "INCONCLUSIVE"
	VerificationSupported    VerificationStatus = "SUPPORTED"
	VerificationContradicted VerificationStatus = "CONTRADICTED"
	VerificationMixed        VerificationStatus = "MIXED"
)

// VerificationEvidence is an explicitly classified fact supplied by an
// investigator. Independent must be true only when the fact is independent of
// the evidence that originally generated the hypothesis.
type VerificationEvidence struct {
	ID          string              `json:"id"`
	Fact        string              `json:"fact"`
	Relation    VerificationRelation `json:"relation"`
	Independent bool                `json:"independent"`
}

// VerificationAssessment preserves both corroboration and contradiction so
// that conflicting evidence is not silently collapsed into a single score.
type VerificationAssessment struct {
	HypothesisID           string              `json:"hypothesis_id"`
	Status                 VerificationStatus  `json:"status"`
	SupportingEvidenceIDs  []string            `json:"supporting_evidence_ids"`
	SupportingFacts        []string            `json:"supporting_facts"`
	ContradictingEvidenceIDs []string          `json:"contradicting_evidence_ids"`
	ContradictingFacts     []string            `json:"contradicting_facts"`
	ExcludedEvidenceIDs    []string            `json:"excluded_evidence_ids"`
	Explanation            string              `json:"explanation"`
	Limitations            string              `json:"limitations"`
}

// Assess evaluates investigator-classified verification evidence without
// changing the hypothesis confidence. Only explicitly independent evidence
// affects status; reused or non-independent evidence is disclosed as excluded.
func (e *HypothesisEngine) Assess(
	hypothesis Hypothesis,
	evidenceRecords []VerificationEvidence,
) (VerificationAssessment, error) {
	if err := hypothesis.Validate(); err != nil {
		return VerificationAssessment{}, fmt.Errorf("invalid hypothesis: %w", err)
	}

	assessment := VerificationAssessment{
		HypothesisID: hypothesis.ID,
		Status: VerificationUnverified,
		SupportingEvidenceIDs: []string{},
		SupportingFacts: []string{},
		ContradictingEvidenceIDs: []string{},
		ContradictingFacts: []string{},
		ExcludedEvidenceIDs: []string{},
		Limitations: "Assessment status summarizes explicitly classified evidence only; it is not a probability or proof. Independence is supplied by the investigator and cannot be established from an evidence ID alone.",
	}
	originalIDs := make(map[string]struct{}, len(hypothesis.SupportingIDs))
	for _, id := range hypothesis.SupportingIDs {
		originalIDs[strings.TrimSpace(id)] = struct{}{}
	}
	seen := make(map[string]struct{}, len(evidenceRecords))
	orderedRecords := append([]VerificationEvidence(nil), evidenceRecords...)
	sort.Slice(orderedRecords, func(i, j int) bool {
		return strings.TrimSpace(orderedRecords[i].ID) < strings.TrimSpace(orderedRecords[j].ID)
	})
	for _, record := range orderedRecords {
		id := strings.TrimSpace(record.ID)
		if id == "" {
			return VerificationAssessment{}, fmt.Errorf("verification evidence ID is required")
		}
		if _, exists := seen[id]; exists {
			return VerificationAssessment{}, fmt.Errorf("duplicate verification evidence ID %q", id)
		}
		seen[id] = struct{}{}
		if strings.TrimSpace(record.Fact) == "" {
			return VerificationAssessment{}, fmt.Errorf("verification evidence %q has no fact", id)
		}
		if record.Relation != VerificationSupports && record.Relation != VerificationContradicts {
			return VerificationAssessment{}, fmt.Errorf("verification evidence %q has invalid relation %q", id, record.Relation)
		}
		_, reused := originalIDs[id]
		if !record.Independent || reused {
			assessment.ExcludedEvidenceIDs = append(assessment.ExcludedEvidenceIDs, id)
			continue
		}
		if record.Relation == VerificationSupports {
			assessment.SupportingEvidenceIDs = append(assessment.SupportingEvidenceIDs, id)
			assessment.SupportingFacts = append(assessment.SupportingFacts, strings.TrimSpace(record.Fact))
		} else {
			assessment.ContradictingEvidenceIDs = append(assessment.ContradictingEvidenceIDs, id)
			assessment.ContradictingFacts = append(assessment.ContradictingFacts, strings.TrimSpace(record.Fact))
		}
	}
	if len(evidenceRecords) == 0 {
		assessment.Explanation = "No verification evidence was supplied; the hypothesis remains unverified."
	} else if len(assessment.SupportingEvidenceIDs) == 0 && len(assessment.ContradictingEvidenceIDs) == 0 {
		assessment.Status = VerificationInconclusive
		assessment.Explanation = "No independent verification evidence was eligible to assess the hypothesis."
	} else {
		switch {
		case len(assessment.SupportingEvidenceIDs) > 0 && len(assessment.ContradictingEvidenceIDs) > 0:
			assessment.Status = VerificationMixed
			assessment.Explanation = "Independent evidence both supports and contradicts the hypothesis; investigate the conflict rather than collapsing it into a single confidence score."
		case len(assessment.SupportingEvidenceIDs) > 0:
			assessment.Status = VerificationSupported
			assessment.Explanation = "Independent evidence supports the hypothesis; this does not establish that it is conclusively true."
		default:
			assessment.Status = VerificationContradicted
			assessment.Explanation = "Independent evidence contradicts the hypothesis; retain the original observations and review whether the hypothesis should be revised or rejected."
		}
	}
	sort.Strings(assessment.ExcludedEvidenceIDs)
	return assessment, nil
}
