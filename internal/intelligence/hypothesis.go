package intelligence

import (
	"fmt"
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

	for _, correlation := range correlations {
		if strings.TrimSpace(correlation.ID) == "" {
			return nil, fmt.Errorf("correlation ID is required")
		}
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
		case CorrelationSharedIPAddress:
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

			hypothesis := Hypothesis{
				ID:    "hypothesis:" + correlation.ID,
				Title: "Potential shared infrastructure",
				Statement: fmt.Sprintf(
					"The entities %s may share or use the same network infrastructure because they were observed resolving to %s.",
					strings.Join(entities, ", "),
					correlation.SharedValue,
				),
				Confidence:    HypothesisConfidenceLow,
				SupportingIDs: evidenceIDs,
				SupportingFacts: []string{
					fmt.Sprintf(
						"%d distinct entities were associated with IP address %s.",
						len(entities),
						correlation.SharedValue,
					),
				},
				Alternative: "The address may belong to a CDN, reverse proxy, shared hosting provider, cloud platform, or other shared service.",
				Limitations: "A shared IP address alone does not prove common ownership, control, a direct relationship, or a security weakness. Confidence is qualitative and is not a probability.",
				Verification: []string{
					"Compare DNS observations over time.",
					"Review authorized, reliable DNS and certificate data for additional independent links.",
					"Check whether the address is associated with shared hosting, a CDN, or a reverse proxy before inferring ownership.",
				},
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
