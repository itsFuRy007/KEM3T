package intelligence

import (
	"fmt"
	"sort"
	"strings"
)

// DiscoveryPivot identifies an intermediate entity that repeatedly appears as
// the bridge in independently discovered multi-hop paths. It is an investigation
// lead, not an ownership or control conclusion.
type DiscoveryPivot struct {
	ID                     string            `json:"id"`
	Type                   string            `json:"type"`
	Pivot                  string            `json:"pivot"`
	ConnectedEntities      []string          `json:"connected_entities"`
	PathIDs                []string          `json:"path_ids"`
	SignalTypes            []CorrelationType `json:"signal_types"`
	SignalDiversity        int               `json:"signal_diversity"`
	Confidence             string            `json:"confidence"`
	Statement              string            `json:"statement"`
	WhyItMatters           string            `json:"why_it_matters"`
	AlternativeExplanations string            `json:"alternative_explanations"`
	Verification            []string          `json:"verification_steps"`
}

func (d DiscoveryPivot) Validate() error {
	if strings.TrimSpace(d.ID) == "" || d.Type != "DISCOVERY_PIVOT" {
		return fmt.Errorf("discovery pivot identity is invalid")
	}
	if strings.TrimSpace(d.Pivot) == "" {
		return fmt.Errorf("discovery pivot entity is required")
	}
	if len(d.ConnectedEntities) < 2 || len(d.PathIDs) < 2 {
		return fmt.Errorf("discovery pivot requires at least two connected entities and paths")
	}
	if d.SignalDiversity < 2 || len(d.SignalTypes) < 2 {
		return fmt.Errorf("discovery pivot requires at least two signal types")
	}
	if strings.TrimSpace(d.Confidence) == "" || strings.TrimSpace(d.Statement) == "" || strings.TrimSpace(d.WhyItMatters) == "" {
		return fmt.Errorf("discovery pivot explanation fields are required")
	}
	if strings.TrimSpace(d.AlternativeExplanations) == "" || len(d.Verification) == 0 {
		return fmt.Errorf("discovery pivot alternatives and verification steps are required")
	}
	return nil
}

// DiscoverPivots finds intermediate entities that recur across multi-hop
// discoveries. Repeated pivots are surfaced only when the surrounding paths
// contain at least two distinct signal types; this prevents duplicate paths
// generated from one dimension from creating false importance.
func (e *DiscoveryEngine) DiscoverPivots(paths []DiscoveryPath, target string) ([]DiscoveryPivot, error) {
	target = normalizeCorrelationEntity(target)
	if target == "" {
		return nil, fmt.Errorf("discovery target is required")
	}

	type pivotAggregate struct {
		paths       map[string]DiscoveryPath
		neighbors   map[string]struct{}
		signalTypes map[CorrelationType]struct{}
	}
	aggregates := make(map[string]*pivotAggregate)
	for _, path := range paths {
		if err := path.Validate(); err != nil {
			return nil, fmt.Errorf("validate discovery path %q: %w", path.ID, err)
		}
		if len(path.Entities) != 3 || path.Entities[0] != target {
			continue
		}
		pivot := normalizeCorrelationEntity(path.Entities[1])
		neighbor := normalizeCorrelationEntity(path.Entities[2])
		if pivot == "" || neighbor == "" || pivot == target || neighbor == target {
			continue
		}
		aggregate := aggregates[pivot]
		if aggregate == nil {
			aggregate = &pivotAggregate{paths: make(map[string]DiscoveryPath), neighbors: make(map[string]struct{}), signalTypes: make(map[CorrelationType]struct{})}
			aggregates[pivot] = aggregate
		}
		aggregate.paths[path.ID] = path
		aggregate.neighbors[neighbor] = struct{}{}
		for _, signalType := range path.SignalTypes {
			aggregate.signalTypes[signalType] = struct{}{}
		}
	}

	results := make([]DiscoveryPivot, 0)
	for pivot, aggregate := range aggregates {
		if len(aggregate.paths) < 2 || len(aggregate.neighbors) < 2 || len(aggregate.signalTypes) < 2 {
			continue
		}
		pathIDs := make([]string, 0, len(aggregate.paths))
		for pathID := range aggregate.paths { pathIDs = append(pathIDs, pathID) }
		sort.Strings(pathIDs)
		neighbors := make([]string, 0, len(aggregate.neighbors))
		for neighbor := range aggregate.neighbors { neighbors = append(neighbors, neighbor) }
		sort.Strings(neighbors)
		signalTypes := make([]CorrelationType, 0, len(aggregate.signalTypes))
		for signalType := range aggregate.signalTypes { signalTypes = append(signalTypes, signalType) }
		sort.Slice(signalTypes, func(i, j int) bool { return signalTypes[i] < signalTypes[j] })

		result := DiscoveryPivot{
			ID: "discovery-pivot:" + target + ":" + pivot,
			Type: "DISCOVERY_PIVOT",
			Pivot: pivot,
			ConnectedEntities: neighbors,
			PathIDs: pathIDs,
			SignalTypes: signalTypes,
			SignalDiversity: len(aggregate.signalTypes),
			Confidence: "LOW",
			Statement: fmt.Sprintf("%s repeatedly appears as an investigation pivot connecting %s to multiple surrounding entities across %d infrastructure dimensions.", pivot, target, len(aggregate.signalTypes)),
			WhyItMatters: "A recurring intermediate entity can reveal a hidden infrastructure hub, provider boundary, certificate-management dependency, or other pivot that is easy to miss when each relationship is investigated independently.",
			AlternativeExplanations: "Shared hosting, CDN infrastructure, certificate-management services, passive-DNS aggregation, mirrored provider data, or other common platforms can cause many unrelated entities to converge on the same pivot.",
			Verification: []string{
				"Inspect every supporting path and trace each hop back to its original evidence and observation time.",
				"Determine whether the pivot represents a shared service or infrastructure provider before treating it as a meaningful relationship.",
				"Look for a direct signal between the target and the connected entities; a pivot alone does not establish endpoint ownership or control.",
				"Compare the pivot across historical observations to distinguish persistent infrastructure from a temporary collection artifact.",
			},
		}
		if err := result.Validate(); err != nil { return nil, err }
		results = append(results, result)
	}

	sort.Slice(results, func(i, j int) bool { return results[i].ID < results[j].ID })
	return results, nil
}
