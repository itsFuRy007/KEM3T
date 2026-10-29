package intelligence

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

// CorrelationType identifies a relationship supported by collected evidence.
type CorrelationType string

const (
	CorrelationSharedIPAddress CorrelationType = "SHARED_IP_ADDRESS"
)

// Correlation represents a relationship between distinct entities.
type Correlation struct {
	ID               string          `json:"id"`
	Type             CorrelationType `json:"type"`
	Entities         []string        `json:"entities"`
	SharedValue      string          `json:"shared_value"`
	EvidenceIDs      []string        `json:"evidence_ids"`
	ObservationIDs   []string        `json:"observation_ids"`
	ObservationCount int             `json:"observation_count"`
	Confidence       string          `json:"confidence"`
	ConfidenceScope  string          `json:"confidence_scope"`
	Explanation      string          `json:"explanation"`
	Limitations      string          `json:"limitations"`
}

// CorrelationEngine discovers relationships in normalized evidence.
type CorrelationEngine struct{}

// Correlate discovers IP addresses associated with multiple entities.
// Results cover the entire registry and are deterministic.
func (e *CorrelationEngine) Correlate(
	registry *evidence.Registry,
) ([]Correlation, error) {
	if registry == nil {
		return nil, fmt.Errorf("evidence registry is required")
	}

	return e.CorrelateEvidence(
		registry.AllEvidence(),
		registry.AllObservations(),
	)
}

// CorrelateForTarget discovers shared-IP relationships that include target.
// Related entities remain visible so the report can provide investigation context,
// but correlations unrelated to the requested target are excluded.
func (e *CorrelationEngine) CorrelateForTarget(
	registry *evidence.Registry,
	target string,
) ([]Correlation, error) {
	if registry == nil {
		return nil, fmt.Errorf("evidence registry is required")
	}
	target = normalizeCorrelationEntity(target)
	if target == "" {
		return nil, fmt.Errorf("correlation target is required")
	}

	return e.correlateEvidence(
		registry.AllEvidence(),
		registry.AllObservations(),
		target,
	)
}

// CorrelateEvidence discovers shared-IP relationships from supplied records.
func (e *CorrelationEngine) CorrelateEvidence(
	records []evidence.Evidence,
	observations []evidence.Observation,
) ([]Correlation, error) {
	return e.correlateEvidence(records, observations, "")
}

// CorrelateEvidenceForTarget discovers shared-IP relationships that include target.
func (e *CorrelationEngine) CorrelateEvidenceForTarget(
	records []evidence.Evidence,
	observations []evidence.Observation,
	target string,
) ([]Correlation, error) {
	target = normalizeCorrelationEntity(target)
	if target == "" {
		return nil, fmt.Errorf("correlation target is required")
	}
	return e.correlateEvidence(records, observations, target)
}

func (e *CorrelationEngine) correlateEvidence(
	records []evidence.Evidence,
	observations []evidence.Observation,
	target string,
) ([]Correlation, error) {
	type evidenceItem struct {
		record       evidence.Evidence
		observations []evidence.Observation
	}

	observationByEvidence := make(map[string][]evidence.Observation)
	seenObservations := make(map[string]struct{}, len(observations))
	for _, observation := range observations {
		if err := observation.Validate(); err != nil {
			return nil, fmt.Errorf("invalid observation %q: %w", observation.ID, err)
		}
		if _, exists := seenObservations[observation.ID]; exists {
			return nil, fmt.Errorf("duplicate observation ID %q", observation.ID)
		}
		seenObservations[observation.ID] = struct{}{}
		observationByEvidence[observation.EvidenceID] = append(
			observationByEvidence[observation.EvidenceID],
			observation,
		)
	}

	byAddress := make(map[string][]evidenceItem)
	seenEvidence := make(map[string]struct{}, len(records))
	for _, record := range records {
		if err := record.Validate(); err != nil {
			return nil, fmt.Errorf("invalid evidence %q: %w", record.ID, err)
		}
		if _, exists := seenEvidence[record.ID]; exists {
			return nil, fmt.Errorf("duplicate evidence ID %q", record.ID)
		}
		seenEvidence[record.ID] = struct{}{}

		if record.Type != evidence.TypeDNSAddress {
			continue
		}

		entity := normalizeCorrelationEntity(record.EntityID)
		ip := net.ParseIP(strings.TrimSpace(record.Value))
		if entity == "" || ip == nil {
			return nil, fmt.Errorf("evidence %q has an empty entity or invalid IP address", record.ID)
		}

		byAddress[ip.String()] = append(byAddress[ip.String()], evidenceItem{
			record:       record,
			observations: observationByEvidence[record.ID],
		})
	}

	results := make([]Correlation, 0)
	for address, items := range byAddress {
		entitiesSet := make(map[string]struct{})
		evidenceIDsSet := make(map[string]struct{})
		observationIDsSet := make(map[string]struct{})

		for _, item := range items {
			entitiesSet[normalizeCorrelationEntity(item.record.EntityID)] = struct{}{}
			evidenceIDsSet[item.record.ID] = struct{}{}
			for _, observation := range item.observations {
				observationIDsSet[observation.ID] = struct{}{}
			}
		}

		if len(entitiesSet) < 2 {
			continue
		}
		if target != "" {
			if _, includesTarget := entitiesSet[target]; !includesTarget {
				continue
			}
		}

		entities := sortedSet(entitiesSet)
		evidenceIDs := sortedSet(evidenceIDsSet)
		observationIDs := sortedSet(observationIDsSet)

		results = append(results, Correlation{
			ID:               "shared-ip:" + address,
			Type:             CorrelationSharedIPAddress,
			Entities:         entities,
			SharedValue:      address,
			EvidenceIDs:      evidenceIDs,
			ObservationIDs:   observationIDs,
			ObservationCount: len(observationIDs),
			// HIGH refers only to confidence that the stored records show the
			// association. It does not indicate common ownership or risk.
			Confidence:      "HIGH",
			ConfidenceScope: "OBSERVED_SHARED_ADDRESS",
			Explanation:     fmt.Sprintf("%d distinct entities were observed resolving to the same normalized IP address.", len(entities)),
			Limitations:     "A shared IP address does not by itself prove common ownership, a direct relationship, or a vulnerability. Confidence applies only to the observed association, not to any ownership or security conclusion.",
		})
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].SharedValue == results[j].SharedValue {
			return results[i].ID < results[j].ID
		}
		return results[i].SharedValue < results[j].SharedValue
	})
	return results, nil
}

func normalizeCorrelationEntity(value string) string {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return value
}

func sortedSet(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
