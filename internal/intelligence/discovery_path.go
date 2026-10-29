package intelligence

import (
	"fmt"
	"sort"
	"strings"
)

// DiscoveryPath is a multi-hop investigation lead. It deliberately describes a
// path through observed relationships rather than claiming that the endpoints
// are directly related.
type DiscoveryPath struct {
	ID                    string             `json:"id"`
	Type                  DiscoveryType     `json:"type"`
	Entities              []string           `json:"entities"`
	CorrelationIDs        []string           `json:"correlation_ids"`
	SignalTypes           []CorrelationType  `json:"signal_types"`
	SignalDiversity       int                `json:"signal_diversity"`
	Confidence             string             `json:"confidence"`
	Statement              string             `json:"statement"`
	WhyItMatters           string             `json:"why_it_matters"`
	AlternativeExplanations string            `json:"alternative_explanations"`
	Verification           []string           `json:"verification_steps"`
}

func (d DiscoveryPath) Validate() error {
	if strings.TrimSpace(d.ID) == "" {
		return fmt.Errorf("discovery path ID is required")
	}
	if d.Type != DiscoveryConvergentInfrastructure {
		return fmt.Errorf("unsupported discovery path type %q", d.Type)
	}
	if len(d.Entities) != 3 {
		return fmt.Errorf("discovery path must contain exactly three entities")
	}
	if len(d.CorrelationIDs) != 2 {
		return fmt.Errorf("discovery path must contain exactly two correlations")
	}
	if len(d.SignalTypes) != 2 || d.SignalTypes[0] == d.SignalTypes[1] {
		return fmt.Errorf("discovery path requires two distinct signal types")
	}
	if d.SignalDiversity != 2 {
		return fmt.Errorf("discovery path signal diversity must be two")
	}
	if strings.TrimSpace(d.Confidence) == "" || strings.TrimSpace(d.Statement) == "" || strings.TrimSpace(d.WhyItMatters) == "" {
		return fmt.Errorf("discovery path explanation fields are required")
	}
	if strings.TrimSpace(d.AlternativeExplanations) == "" || len(d.Verification) == 0 {
		return fmt.Errorf("discovery path alternatives and verification steps are required")
	}
	return nil
}

type discoveryEdge struct {
	from, to string
	correlation Correlation
}

// DiscoverPaths finds two-hop relationships from the target where each hop is
// a different infrastructure dimension. This catches cases such as:
// target -> shared IP -> host B -> shared TLS -> host C.
// The result is a lead for investigation, not a claim that target and C share
// infrastructure directly.
func (e *DiscoveryEngine) DiscoverPaths(correlations []Correlation, target string) ([]DiscoveryPath, error) {
	target = normalizeCorrelationEntity(target)
	if target == "" {
		return nil, fmt.Errorf("discovery target is required")
	}

	adjacency := make(map[string][]discoveryEdge)
	for _, correlation := range correlations {
		if err := validateDiscoveryCorrelation(correlation); err != nil {
			return nil, fmt.Errorf("validate correlation %q: %w", correlation.ID, err)
		}
		entities := make([]string, 0, len(correlation.Entities))
		seen := make(map[string]struct{}, len(correlation.Entities))
		for _, entity := range correlation.Entities {
			entity = normalizeCorrelationEntity(entity)
			if entity == "" { continue }
			if _, ok := seen[entity]; ok { continue }
			seen[entity] = struct{}{}
			entities = append(entities, entity)
		}
		for i := range entities {
			for j := i + 1; j < len(entities); j++ {
				adjacency[entities[i]] = append(adjacency[entities[i]], discoveryEdge{from: entities[i], to: entities[j], correlation: correlation})
				adjacency[entities[j]] = append(adjacency[entities[j]], discoveryEdge{from: entities[j], to: entities[i], correlation: correlation})
			}
		}
	}

	resultsByID := make(map[string]DiscoveryPath)
	for _, first := range adjacency[target] {
		for _, second := range adjacency[first.to] {
			if second.to == target || second.to == first.from { continue }
			if correlationDimension(first.correlation.Type) == correlationDimension(second.correlation.Type) { continue }

			// A path is only interesting if the intermediate node is the actual
			// bridge. Direct target->endpoint convergence is already handled by
			// Discover and should not be duplicated here.
			if !containsEntity(first.correlation.Entities, target) || !containsEntity(second.correlation.Entities, first.to) { continue }

			entities := []string{target, first.to, second.to}
			id := "discovery:path:" + strings.Join(entities, "|") + ":" + first.correlation.ID + ":" + second.correlation.ID
			if _, exists := resultsByID[id]; exists { continue }

			path := DiscoveryPath{
				ID: id,
				Type: DiscoveryConvergentInfrastructure,
				Entities: entities,
				CorrelationIDs: []string{first.correlation.ID, second.correlation.ID},
				SignalTypes: []CorrelationType{first.correlation.Type, second.correlation.Type},
				SignalDiversity: 2,
				Confidence: "LOW",
				Statement: fmt.Sprintf("%s reaches %s through %s, and %s is connected to %s through a different infrastructure dimension (%s).", target, first.to, first.correlation.Type, first.to, second.to, second.correlation.Type),
				WhyItMatters: "KEM3T found a multi-hop infrastructure path that is easy to miss when relationships are inspected one correlation at a time. The intermediate entity may be a useful pivot for discovering infrastructure or ownership context around the target.",
				AlternativeExplanations: "Shared providers, CDNs, certificate-management platforms, common hosting, mirrored datasets, or unrelated tenants can create a path without any meaningful relationship between the endpoints.",
				Verification: []string{
					"Inspect both correlations and their evidence timestamps before treating the path as meaningful.",
					"Investigate the intermediate entity independently; it is the pivot that connects the two observed relationships.",
					"Check whether either hop is explained by a common provider, CDN, certificate manager, or other shared service.",
					"Look for an independent signal that connects the endpoints directly before asserting a relationship between them.",
				},
			}
			if err := path.Validate(); err != nil { return nil, err }
			resultsByID[id] = path
		}
	}

	results := make([]DiscoveryPath, 0, len(resultsByID))
	for _, result := range resultsByID { results = append(results, result) }
	sort.Slice(results, func(i, j int) bool { return results[i].ID < results[j].ID })
	return results, nil
}
