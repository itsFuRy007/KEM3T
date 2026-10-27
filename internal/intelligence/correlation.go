package intelligence

import (
	"fmt"
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
	Explanation      string          `json:"explanation"`
	Limitations      string          `json:"limitations"`
}

// CorrelationEngine discovers relationships in normalized evidence.
type CorrelationEngine struct{}

// Correlate discovers IP addresses associated with multiple entities.
//
// Evidence and observations are read from the registry. The engine does not
// modify the registry and returns deterministic results.
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

// CorrelateEvidence discovers shared-IP relationships from supplied records.
func (e *CorrelationEngine) CorrelateEvidence(
	records []evidence.Evidence,
	observations []evidence.Observation,
) ([]Correlation, error) {
	type evidenceItem struct {
		record       evidence.Evidence
		observations []evidence.Observation
	}

	observationByEvidence := make(map[string][]evidence.Observation)
	for _, observation := range observations {
		if err := observation.Validate(); err != nil {
			return nil, fmt.Errorf("invalid observation %q: %w", observation.ID, err)
		}
		observationByEvidence[observation.EvidenceID] = append(
			observationByEvidence[observation.EvidenceID],
			observation,
		)
	}

	byAddress := make(map[string][]evidenceItem)

	for _, record := range records {
		if err := record.Validate(); err != nil {
			return nil, fmt.Errorf("invalid evidence %q: %w", record.ID, err)
		}

		if record.Type != evidence.TypeDNSAddress {
			continue
		}

		entity := strings.ToLower(strings.TrimSpace(record.EntityID))
		address := strings.TrimSpace(record.Value)
		if entity == "" || address == "" {
			return nil, fmt.Errorf("evidence %q has an empty entity or value", record.ID)
		}

		byAddress[address] = append(byAddress[address], evidenceItem{
			record:       record,
			observations: observationByEvidence[record.ID],
		})
	}

	results := make([]Correlation, 0)

	for address, items := range byAddress {
		entitiesSet := make(map[string]struct{})
		evidenceIDsSet := make(map[string]struct{})
		observationIDsSet := make(map[string]struct{})
		observationCount := 0

		for _, item := range items {
			entitiesSet[strings.ToLower(strings.TrimSpace(item.record.EntityID))] = struct{}{}
			evidenceIDsSet[item.record.ID] = struct{}{}
			for _, observation := range item.observations {
				observationIDsSet[observation.ID] = struct{}{}
				observationCount++
			}
		}

		if len(entitiesSet) < 2 {
			continue
		}

		entities := make([]string, 0, len(entitiesSet))
		for entity := range entitiesSet {
			entities = append(entities, entity)
		}
		sort.Strings(entities)

		evidenceIDs := make([]string, 0, len(evidenceIDsSet))
		for id := range evidenceIDsSet {
			evidenceIDs = append(evidenceIDs, id)
		}
		sort.Strings(evidenceIDs)

		observationIDs := make([]string, 0, len(observationIDsSet))
		for id := range observationIDsSet {
			observationIDs = append(observationIDs, id)
		}
		sort.Strings(observationIDs)

		results = append(results, Correlation{
			ID:               "shared-ip:" + address,
			Type:             CorrelationSharedIPAddress,
			Entities:         entities,
			SharedValue:      address,
			EvidenceIDs:      evidenceIDs,
			ObservationIDs:   observationIDs,
			ObservationCount: observationCount,
			Confidence:       "HIGH",
			Explanation:      fmt.Sprintf("%d distinct entities were observed resolving to the same IP address.", len(entities)),
			Limitations:      "A shared IP address does not by itself prove common ownership, a direct relationship, or a vulnerability.",
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
