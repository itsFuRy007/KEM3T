package graph

import "testing"

func TestEntityAndRelationshipLookupExposeExistingGraphModel(t *testing.T) {
	graph := Graph{
		Nodes: []Node{
			{ID: "domain:example.com", Type: NodeDomain, Value: "example.com"},
			{ID: "ip:192.0.2.10", Type: NodeIP, Value: "192.0.2.10"},
		},
		Edges: []Edge{
			{
				ID:          "resolves-to:example.com:192.0.2.10",
				Type:        EdgeResolvesTo,
				Source:      "domain:example.com",
				Target:      "ip:192.0.2.10",
				EvidenceIDs: []string{"dns-2", "dns-9"},
			},
		},
	}

	node, err := Entity(graph, "domain:example.com")
	if err != nil {
		t.Fatalf("Entity() returned error: %v", err)
	}
	if node.Type != NodeDomain || node.Value != "example.com" {
		t.Fatalf("unexpected entity: %+v", node)
	}

	edge, err := Relationship(graph, "resolves-to:example.com:192.0.2.10")
	if err != nil {
		t.Fatalf("Relationship() returned error: %v", err)
	}
	if edge.Type != EdgeResolvesTo || edge.Target != "ip:192.0.2.10" {
		t.Fatalf("unexpected relationship: %+v", edge)
	}
}

func TestRelationshipProvenanceReturnsDeterministicReferences(t *testing.T) {
	graph := Graph{
		Nodes: []Node{
			{ID: "domain:example.com", Type: NodeDomain, Value: "example.com"},
			{ID: "ip:192.0.2.10", Type: NodeIP, Value: "192.0.2.10"},
		},
		Edges: []Edge{
			{
				ID:             "resolves-to:example.com:192.0.2.10",
				Type:           EdgeResolvesTo,
				Source:         "domain:example.com",
				Target:         "ip:192.0.2.10",
				EvidenceIDs:    []string{"dns-2", "dns-9"},
				ObservationIDs: []string{"obs-1", "obs-3"},
			},
		},
	}

	provenance, err := RelationshipProvenance(graph, "resolves-to:example.com:192.0.2.10")
	if err != nil {
		t.Fatalf("RelationshipProvenance() returned error: %v", err)
	}

	if got, want := provenance.EvidenceIDs, []string{"dns-2", "dns-9"}; !equalStrings(got, want) {
		t.Fatalf("evidence provenance = %v, want %v", got, want)
	}
	if got, want := provenance.ObservationIDs, []string{"obs-1", "obs-3"}; !equalStrings(got, want) {
		t.Fatalf("observation provenance = %v, want %v", got, want)
	}

	provenance.EvidenceIDs[0] = "mutated"
	provenance.ObservationIDs[0] = "mutated"
	if edge := graph.Edges[0]; edge.EvidenceIDs[0] != "dns-2" || edge.ObservationIDs[0] != "obs-1" {
		t.Fatal("provenance result aliases graph-owned slices")
	}
}

func TestGraphLookupRejectsMissingEntitiesAndRelationships(t *testing.T) {
	graph := Graph{
		Nodes: []Node{{ID: "domain:example.com", Type: NodeDomain, Value: "example.com"}},
	}

	if _, err := Entity(graph, "domain:missing.example.com"); err == nil {
		t.Fatal("expected missing entity to be rejected")
	}
	if _, err := Relationship(graph, "missing"); err == nil {
		t.Fatal("expected missing relationship to be rejected")
	}
}

func equalStrings(got, want []string) bool {
	if len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
