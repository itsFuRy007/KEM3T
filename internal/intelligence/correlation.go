package intelligence

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

// CorrelationType identifies a relationship supported by collected evidence.
type CorrelationType string

const (
	CorrelationSharedIPAddress             CorrelationType = "SHARED_IP_ADDRESS"
	CorrelationSharedTLSCertificateFingerprint CorrelationType = "SHARED_TLS_CERTIFICATE_FINGERPRINT"
)

// Correlation represents a relationship between distinct entities.
type Correlation struct {
	ID               string          `json:"id"`
	Type             CorrelationType `json:"type"`
	Entities         []string        `json:"entities"`
	SharedValue      string          `json:"shared_value"`
	EvidenceIDs      []string        `json:"evidence_ids"`
	ObservationIDs   []string        `json:"observation_ids"`
	ObservationCount    int             `json:"observation_count"`
	SourceNames         []string        `json:"source_names"`
	DistinctSourceCount int             `json:"distinct_source_count"`
	Confidence          string          `json:"confidence"`
	ConfidenceScope  string          `json:"confidence_scope"`
	Explanation      string          `json:"explanation"`
	Limitations      string          `json:"limitations"`
}

type correlationEvidenceItem struct {
	record       evidence.Evidence
	observations []evidence.Observation
}

// CorrelationEngine discovers evidence-backed relationships between entities.
type CorrelationEngine struct{}

// Correlate discovers relationships across the complete evidence registry.
func (e *CorrelationEngine) Correlate(registry *evidence.Registry) ([]Correlation, error) {
	if registry == nil {
		return nil, fmt.Errorf("evidence registry is required")
	}
	return e.CorrelateEvidence(registry.AllEvidence(), registry.AllObservations())
}

// CorrelateForTarget discovers relationships that include target. Related
// entities remain visible as investigation context; unrelated groups are omitted.
func (e *CorrelationEngine) CorrelateForTarget(registry *evidence.Registry, target string) ([]Correlation, error) {
	if registry == nil {
		return nil, fmt.Errorf("evidence registry is required")
	}
	target = normalizeCorrelationEntity(target)
	if target == "" {
		return nil, fmt.Errorf("correlation target is required")
	}
	return e.correlateEvidence(registry.AllEvidence(), registry.AllObservations(), target)
}

// CorrelateEvidence discovers relationships from supplied evidence and provenance.
func (e *CorrelationEngine) CorrelateEvidence(records []evidence.Evidence, observations []evidence.Observation) ([]Correlation, error) {
	return e.correlateEvidence(records, observations, "")
}

// CorrelateEvidenceForTarget discovers relationships that include target.
func (e *CorrelationEngine) CorrelateEvidenceForTarget(records []evidence.Evidence, observations []evidence.Observation, target string) ([]Correlation, error) {
	target = normalizeCorrelationEntity(target)
	if target == "" {
		return nil, fmt.Errorf("correlation target is required")
	}
	return e.correlateEvidence(records, observations, target)
}

func (e *CorrelationEngine) correlateEvidence(records []evidence.Evidence, observations []evidence.Observation, target string) ([]Correlation, error) {
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
		observationByEvidence[observation.EvidenceID] = append(observationByEvidence[observation.EvidenceID], observation)
	}

	byAddress := make(map[string][]correlationEvidenceItem)
	byFingerprint := make(map[string][]correlationEvidenceItem)
	seenEvidence := make(map[string]struct{}, len(records))
	for _, record := range records {
		if err := record.Validate(); err != nil {
			return nil, fmt.Errorf("invalid evidence %q: %w", record.ID, err)
		}
		if _, exists := seenEvidence[record.ID]; exists {
			return nil, fmt.Errorf("duplicate evidence ID %q", record.ID)
		}
		seenEvidence[record.ID] = struct{}{}

		item := correlationEvidenceItem{record: record, observations: observationByEvidence[record.ID]}
		switch record.Type {
		case evidence.TypeDNSAddress:
			entity := normalizeCorrelationEntity(record.EntityID)
			ip := net.ParseIP(strings.TrimSpace(record.Value))
			if entity == "" || ip == nil {
				return nil, fmt.Errorf("evidence %q has an empty entity or invalid IP address", record.ID)
			}
			byAddress[ip.String()] = append(byAddress[ip.String()], item)
		case evidence.TypeTLSCertificate:
			var details evidence.TLSCertificateDetails
			if err := json.Unmarshal([]byte(record.Value), &details); err != nil {
				return nil, fmt.Errorf("decode TLS evidence %q: %w", record.ID, err)
			}
			fingerprint := strings.ToLower(strings.TrimSpace(details.SHA256Fingerprint))
			if len(fingerprint) != 64 {
				return nil, fmt.Errorf("TLS evidence %q has an invalid SHA-256 certificate fingerprint length", record.ID)
			}
			if _, err := hex.DecodeString(fingerprint); err != nil {
				return nil, fmt.Errorf("TLS evidence %q has a non-hexadecimal SHA-256 certificate fingerprint", record.ID)
			}
			if normalizeCorrelationEntity(record.EntityID) == "" {
				return nil, fmt.Errorf("TLS evidence %q has an empty entity", record.ID)
			}
			byFingerprint[fingerprint] = append(byFingerprint[fingerprint], item)
		}
	}

	for _, observation := range observations {
		if _, exists := seenEvidence[observation.EvidenceID]; !exists {
			return nil, fmt.Errorf("observation %q references missing evidence %q", observation.ID, observation.EvidenceID)
		}
	}

	results := make([]Correlation, 0)
	results = append(results, buildCorrelations(
		byAddress, target, CorrelationSharedIPAddress, "shared-ip:",
		"OBSERVED_SHARED_ADDRESS",
		"%d distinct entities were observed resolving to the same normalized IP address.",
		"A shared IP address does not by itself prove common ownership, a direct relationship, or a vulnerability. Confidence applies only to the observed association, not to any ownership or security conclusion. Distinct source labels are reported as collection context and do not prove independent corroboration.",
	)...)
	results = append(results, buildCorrelations(
		byFingerprint, target, CorrelationSharedTLSCertificateFingerprint, "shared-tls-cert:",
		"OBSERVED_SHARED_CERTIFICATE_FINGERPRINT",
		"%d distinct entities were observed presenting the same TLS certificate SHA-256 fingerprint.",
		"A matching certificate fingerprint establishes that the same certificate was observed, not common ownership or a vulnerability. Certificates may be centrally managed or reused across unrelated services; verify with independent evidence. Distinct source labels are reported as collection context and do not prove independent corroboration.",
	)...)

	sort.Slice(results, func(i, j int) bool {
		if results[i].Type != results[j].Type {
			return results[i].Type < results[j].Type
		}
		if results[i].SharedValue != results[j].SharedValue {
			return results[i].SharedValue < results[j].SharedValue
		}
		return results[i].ID < results[j].ID
	})
	return results, nil
}

func buildCorrelations(groups map[string][]correlationEvidenceItem, target string, correlationType CorrelationType, idPrefix, confidenceScope, explanationTemplate, limitations string) []Correlation {
	results := make([]Correlation, 0)
	for sharedValue, items := range groups {
		entitiesSet := make(map[string]struct{})
		evidenceIDsSet := make(map[string]struct{})
		observationIDsSet := make(map[string]struct{})
		sourceNamesSet := make(map[string]struct{})
		for _, item := range items {
			entitiesSet[normalizeCorrelationEntity(item.record.EntityID)] = struct{}{}
			evidenceIDsSet[item.record.ID] = struct{}{}
			for _, observation := range item.observations {
				observationIDsSet[observation.ID] = struct{}{}
				source := strings.TrimSpace(observation.Source)
				if source != "" {
					sourceNamesSet[source] = struct{}{}
				}
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
		results = append(results, Correlation{
			ID: idPrefix + sharedValue, Type: correlationType, Entities: entities, SharedValue: sharedValue,
			EvidenceIDs: sortedSet(evidenceIDsSet), ObservationIDs: sortedSet(observationIDsSet),
			ObservationCount: len(observationIDsSet), SourceNames: sortedSet(sourceNamesSet),
			DistinctSourceCount: len(sourceNamesSet), Confidence: "HIGH", ConfidenceScope: confidenceScope,
			Explanation: fmt.Sprintf(explanationTemplate, len(entities)), Limitations: limitations,
		})
	}
	return results
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
