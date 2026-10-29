package graph

import (
	"fmt"
	"sort"
)

// Provenance describes the evidence and normalized observations that support
// an infrastructure relationship. It contains references only; source records
// remain owned by the evidence layer.
type Provenance struct {
	EvidenceIDs    []string `json:"evidence_ids"`
	ObservationIDs []string `json:"observation_ids"`
}

// Entity returns a graph entity by ID after validating the graph.
func Entity(g Graph, nodeID string) (Node, error) {
	if err := g.Validate(); err != nil {
		return Node{}, fmt.Errorf("validate graph before entity lookup: %w", err)
	}
	for _, node := range g.Nodes {
		if node.ID == nodeID {
			return node, nil
		}
	}
	return Node{}, fmt.Errorf("entity %q does not exist", nodeID)
}

// Relationship returns a graph relationship by ID after validating the graph.
// Slice fields are copied so callers cannot mutate graph-owned provenance.
func Relationship(g Graph, edgeID string) (Edge, error) {
	if err := g.Validate(); err != nil {
		return Edge{}, fmt.Errorf("validate graph before relationship lookup: %w", err)
	}
	for _, edge := range g.Edges {
		if edge.ID == edgeID {
			edge.EvidenceIDs = append([]string(nil), edge.EvidenceIDs...)
			edge.ObservationIDs = append([]string(nil), edge.ObservationIDs...)
			return edge, nil
		}
	}
	return Edge{}, fmt.Errorf("relationship %q does not exist", edgeID)
}

// RelationshipProvenance returns deterministic, independently-owned
// references supporting a relationship.
func RelationshipProvenance(g Graph, edgeID string) (Provenance, error) {
	edge, err := Relationship(g, edgeID)
	if err != nil {
		return Provenance{}, err
	}
	return Provenance{
		EvidenceIDs:    sortedCopy(edge.EvidenceIDs),
		ObservationIDs: sortedCopy(edge.ObservationIDs),
	}, nil
}

func sortedCopy(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	return result
}
