package intelligence

import (
	"fmt"
	"sort"
	"strings"
)

// DiscoveryType identifies an emergent relationship that is stronger than any
// single correlation rule but still requires investigator verification.
type DiscoveryType string

const (
	DiscoveryConvergentInfrastructure DiscoveryType = "CONVERGENT_INFRASTRUCTURE"
)

// Discovery represents a cross-signal lead surfaced by combining distinct
// correlation dimensions. It is deliberately not a verdict or probability.
type Discovery struct {
	ID                     string           `json:"id"`
	Type                   DiscoveryType    `json:"type"`
	Entities               []string         `json:"entities"`
	SignalTypes            []CorrelationType `json:"signal_types"`
	CorrelationIDs         []string         `json:"correlation_ids"`
	SharedValues           []string         `json:"shared_values"`
	SignalDiversity        int              `json:"signal_diversity"`
	Confidence             string           `json:"confidence"`
	Statement              string           `json:"statement"`
	WhyItMatters           string           `json:"why_it_matters"`
	AlternativeExplanations string          `json:"alternative_explanations"`
	Verification            []string         `json:"verification_steps"`
}

// Validate checks that a discovery is complete and traceable to correlations.
func (d Discovery) Validate() error {
	if strings.TrimSpace(d.ID) == "" {
		return fmt.Errorf("discovery ID is required")
	}
	if d.Type != DiscoveryConvergentInfrastructure {
		return fmt.Errorf("unsupported discovery type %q", d.Type)
	}
	if len(d.Entities) != 2 || strings.TrimSpace(d.Entities[0]) == "" || strings.TrimSpace(d.Entities[1]) == "" {
		return fmt.Errorf("discovery must reference exactly two non-empty entities")
	}
	if len(d.SignalTypes) < 2 || len(d.CorrelationIDs) < 2 || len(d.SharedValues) < 2 {
		return fmt.Errorf("discovery must contain at least two supporting signals")
	}
	if d.SignalDiversity < 2 {
		return fmt.Errorf("discovery signal diversity must be at least two")
	}
	if strings.TrimSpace(d.Confidence) == "" || strings.TrimSpace(d.Statement) == "" || strings.TrimSpace(d.WhyItMatters) == "" {
		return fmt.Errorf("discovery explanation fields are required")
	}
	if strings.TrimSpace(d.AlternativeExplanations) == "" || len(d.Verification) == 0 {
		return fmt.Errorf("discovery alternatives and verification steps are required")
	}
	for _, step := range d.Verification {
		if strings.TrimSpace(step) == "" {
			return fmt.Errorf("discovery verification steps must not be empty")
		}
	}
	return nil
}

type discoveryPair struct {
	entities map[string]struct{}
	byType   map[CorrelationType][]Correlation
}

// Discover combines correlations into higher-order leads. The key idea is
// signal convergence: a relationship observed across different infrastructure
// dimensions is surfaced even when no single correlation rule considers it
// remarkable. Correlation types are grouped into dimensions so repeated data
// from one dimension cannot masquerade as independent corroboration.
type DiscoveryEngine struct{}

func (e *DiscoveryEngine) Discover(correlations []Correlation, target string) ([]Discovery, error) {
	target = normalizeCorrelationEntity(target)
	if target == "" {
		return nil, fmt.Errorf("discovery target is required")
	}

	pairs := make(map[string]*discoveryPair)
	for _, correlation := range correlations {
		if err := validateDiscoveryCorrelation(correlation); err != nil {
			return nil, fmt.Errorf("validate correlation %q: %w", correlation.ID, err)
		}
		if !containsEntity(correlation.Entities, target) {
			continue
		}

		for _, entity := range correlation.Entities {
			entity = normalizeCorrelationEntity(entity)
			if entity == "" || entity == target {
				continue
			}
			key := pairKey(target, entity)
			pair := pairs[key]
			if pair == nil {
				pair = &discoveryPair{entities: map[string]struct{}{target: {}, entity: {}}, byType: make(map[CorrelationType][]Correlation)}
				pairs[key] = pair
			}
			pair.byType[correlation.Type] = append(pair.byType[correlation.Type], correlation)
		}
	}

	results := make([]Discovery, 0)
	for _, pair := range pairs {
		dimensions := make(map[string]struct{})
		allTypes := make([]CorrelationType, 0)
		correlationIDs := make([]string, 0)
		sharedValues := make([]string, 0)
		for correlationType, group := range pair.byType {
			for _, correlation := range group {
				allTypes = append(allTypes, correlationType)
				correlationIDs = append(correlationIDs, correlation.ID)
				sharedValues = append(sharedValues, correlation.SharedValue)
				dimensions[correlationDimension(correlationType)] = struct{}{}
			}
		}
		if len(dimensions) < 2 {
			continue
		}
		allTypes = uniqueCorrelationTypes(allTypes)
		sort.Strings(correlationIDs)
		correlationIDs = uniqueStrings(correlationIDs)
		sort.Strings(sharedValues)
		sharedValues = uniqueStrings(sharedValues)
		entities := []string{target}
		for entity := range pair.entities {
			if entity != target {
				entities = append(entities, entity)
			}
		}
		sort.Strings(entities)

		discovery := Discovery{
			ID: "discovery:convergent:" + strings.Join(entities, "|"),
			Type: DiscoveryConvergentInfrastructure,
			Entities: entities,
			SignalTypes: allTypes,
			CorrelationIDs: correlationIDs,
			SharedValues: sharedValues,
			SignalDiversity: len(dimensions),
			Confidence: "MODERATE",
			Statement: fmt.Sprintf("%s and %s are connected by infrastructure signals across %d distinct dimensions: %s.", entities[0], entities[1], len(dimensions), strings.Join(sortedStrings(dimensions), ", ")),
			WhyItMatters: "No single correlation had to be decisive: KEM3T surfaced this relationship because the same pair reappears across different evidence dimensions. This is a higher-value investigation lead than an isolated shared-IP or shared-certificate observation.",
			AlternativeExplanations: "Managed hosting, CDN or reverse-proxy infrastructure, wildcard or centrally managed certificates, certificate transparency reuse, mirrored provider data, or unrelated tenants can create convergent signals without common ownership.",
			Verification: []string{
				"Inspect the supporting correlations and their evidence timestamps rather than treating the discovery itself as evidence.",
				"Check whether the signals come from genuinely different infrastructure dimensions; repeated observations from the same provider do not become independent corroboration.",
				"Compare current and historical observations to determine whether the relationship is persistent, transient, or only an artifact of one collection window.",
				"Seek an independent organizational, network-ownership, or service-level signal before asserting a specific relationship.",
			},
		}
		if err := discovery.Validate(); err != nil {
			return nil, err
		}
		results = append(results, discovery)
	}

	sort.Slice(results, func(i, j int) bool { return results[i].ID < results[j].ID })
	return results, nil
}

func validateDiscoveryCorrelation(correlation Correlation) error {
	if strings.TrimSpace(correlation.ID) == "" || len(correlation.Entities) < 2 || strings.TrimSpace(correlation.SharedValue) == "" {
		return fmt.Errorf("correlation is incomplete")
	}
	if correlation.Type == "" {
		return fmt.Errorf("correlation type is required")
	}
	return nil
}

func containsEntity(entities []string, target string) bool {
	for _, entity := range entities {
		if normalizeCorrelationEntity(entity) == target {
			return true
		}
	}
	return false
}

func pairKey(a, b string) string {
	if a > b { a, b = b, a }
	return a + "\x00" + b
}

func correlationDimension(t CorrelationType) string {
	switch t {
	case CorrelationSharedIPAddress:
		return "current-address"
	case CorrelationSharedHistoricalIPAddress:
		return "historical-address"
	case CorrelationSharedTLSCertificateFingerprint:
		return "tls-certificate"
	case CorrelationSharedCTCertificateRecord:
		return "certificate-transparency"
	default:
		return string(t)
	}
}

func uniqueCorrelationTypes(values []CorrelationType) []CorrelationType {
	seen := make(map[CorrelationType]struct{}, len(values))
	result := make([]CorrelationType, 0, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok { continue }
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Slice(result, func(i, j int) bool { return result[i] < result[j] })
	return result
}

func sortedStrings(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values { result = append(result, value) }
	sort.Strings(result)
	return result
}
