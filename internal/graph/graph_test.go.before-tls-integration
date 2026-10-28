package graph

import (
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

func TestBuildCreatesDNSGraph(t *testing.T) {
	records := []evidence.Evidence{
		{
			ID:       "evidence-1",
			EntityID: "example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.10",
		},
		{
			ID:       "evidence-2",
			EntityID: "api.example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.10",
		},
	}

	observations := []evidence.Observation{
		{
			ID:         "observation-1",
			EvidenceID: "evidence-1",
			Source:     "dns",
			ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			EventIDs:   []string{"event-1"},
		},
	}

	got, err := Build(records, observations)
	if err != nil {
		t.Fatalf("Build() returned error: %v", err)
	}

	if len(got.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(got.Nodes))
	}

	if len(got.Edges) != 2 {
		t.Fatalf("expected 2 edges, got %d", len(got.Edges))
	}

	if err := got.Validate(); err != nil {
		t.Fatalf("generated graph is invalid: %v", err)
	}

	foundObservation := false
	for _, edge := range got.Edges {
		if edge.ID == "resolves-to:example.com:192.0.2.10" {
			if len(edge.EvidenceIDs) != 1 || edge.EvidenceIDs[0] != "evidence-1" {
				t.Fatalf("unexpected evidence references: %v", edge.EvidenceIDs)
			}
			if len(edge.ObservationIDs) != 1 || edge.ObservationIDs[0] != "observation-1" {
				t.Fatalf("unexpected observation references: %v", edge.ObservationIDs)
			}
			foundObservation = true
		}
	}

	if !foundObservation {
		t.Fatal("expected edge for example.com was not found")
	}
}

func TestBuildRejectsObservationWithMissingEvidence(t *testing.T) {
	observation := evidence.Observation{
		ID:         "observation-1",
		EvidenceID: "missing-evidence",
		Source:     "dns",
		ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		EventIDs:   []string{"event-1"},
	}

	if _, err := Build(nil, []evidence.Observation{observation}); err == nil {
		t.Fatal("expected observation referencing missing evidence to be rejected")
	}
}

func TestBuildAllowsEvidenceWithoutObservations(t *testing.T) {
	record := evidence.Evidence{
		ID:       "evidence-1",
		EntityID: "example.com",
		Type:     evidence.TypeDNSAddress,
		Value:    "192.0.2.10",
	}

	got, err := Build([]evidence.Evidence{record}, nil)
	if err != nil {
		t.Fatalf("Build() returned error: %v", err)
	}
	if len(got.Edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(got.Edges))
	}
	if len(got.Edges[0].ObservationIDs) != 0 {
		t.Fatalf("expected no observation references, got %v", got.Edges[0].ObservationIDs)
	}
}
func TestBuildRejectsInvalidEvidence(t *testing.T) {
	records := []evidence.Evidence{
		{
			ID:       "invalid",
			EntityID: "example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "not-an-ip",
		},
	}

	if _, err := Build(records, nil); err == nil {
		t.Fatal("expected invalid evidence to be rejected")
	}
}

func TestBuildRejectsDuplicateEvidenceIDs(t *testing.T) {
	record := evidence.Evidence{
		ID:       "duplicate",
		EntityID: "example.com",
		Type:     evidence.TypeDNSAddress,
		Value:    "192.0.2.10",
	}

	if _, err := Build([]evidence.Evidence{record, record}, nil); err == nil {
		t.Fatal("expected duplicate evidence IDs to be rejected")
	}
}

func TestBuildRejectsDuplicateObservationIDs(t *testing.T) {
	observation := evidence.Observation{
		ID:         "duplicate",
		EvidenceID: "evidence-1",
		Source:     "dns",
		ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		EventIDs:   []string{"event-1"},
	}

	if _, err := Build(nil, []evidence.Observation{observation, observation}); err == nil {
		t.Fatal("expected duplicate observation IDs to be rejected")
	}
}

func TestBuildFromRegistryRejectsNilRegistry(t *testing.T) {
	if _, err := BuildFromRegistry(nil); err == nil {
		t.Fatal("expected nil registry to be rejected")
	}
}

func TestBuildIsDeterministicAcrossInputOrder(t *testing.T) {
	records := []evidence.Evidence{
		{ID: "evidence-b", EntityID: "example.com", Type: evidence.TypeDNSAddress, Value: "192.0.2.10"},
		{ID: "evidence-a", EntityID: "EXAMPLE.COM", Type: evidence.TypeDNSAddress, Value: "192.0.2.10"},
	}
	observations := []evidence.Observation{
		{ID: "observation-b", EvidenceID: "evidence-b", Source: "dns", ObservedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), EventIDs: []string{"event-b"}},
		{ID: "observation-a", EvidenceID: "evidence-a", Source: "dns", ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), EventIDs: []string{"event-a"}},
	}

	first, err := Build(records, observations)
	if err != nil {
		t.Fatalf("Build() first call returned error: %v", err)
	}

	reversedRecords := []evidence.Evidence{records[1], records[0]}
	reversedObservations := []evidence.Observation{observations[1], observations[0]}
	second, err := Build(reversedRecords, reversedObservations)
	if err != nil {
		t.Fatalf("Build() second call returned error: %v", err)
	}

	if len(first.Nodes) != len(second.Nodes) || len(first.Edges) != len(second.Edges) {
		t.Fatal("graph output sizes differ when input order changes")
	}
	for i := range first.Nodes {
		if first.Nodes[i] != second.Nodes[i] {
			t.Fatalf("node order differs at index %d", i)
		}
	}
	for i := range first.Edges {
		a, b := first.Edges[i], second.Edges[i]
		if a.ID != b.ID || a.Type != b.Type || a.Source != b.Source || a.Target != b.Target {
			t.Fatalf("edge differs at index %d", i)
		}
		if len(a.EvidenceIDs) != len(b.EvidenceIDs) || len(a.ObservationIDs) != len(b.ObservationIDs) {
			t.Fatalf("edge references differ at index %d", i)
		}
		for j := range a.EvidenceIDs {
			if a.EvidenceIDs[j] != b.EvidenceIDs[j] {
				t.Fatalf("evidence references differ at edge %d", i)
			}
		}
		for j := range a.ObservationIDs {
			if a.ObservationIDs[j] != b.ObservationIDs[j] {
				t.Fatalf("observation references differ at edge %d", i)
			}
		}
	}
}

func TestBuildAggregatesEvidenceAndObservations(t *testing.T) {
	records := []evidence.Evidence{
		{ID: "evidence-a", EntityID: "example.com", Type: evidence.TypeDNSAddress, Value: "192.0.2.10"},
		{ID: "evidence-b", EntityID: "EXAMPLE.COM", Type: evidence.TypeDNSAddress, Value: "192.0.2.10"},
	}
	observations := []evidence.Observation{
		{ID: "observation-a", EvidenceID: "evidence-a", Source: "dns", ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), EventIDs: []string{"event-a"}},
		{ID: "observation-b", EvidenceID: "evidence-b", Source: "dns", ObservedAt: time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC), EventIDs: []string{"event-b"}},
	}

	got, err := Build(records, observations)
	if err != nil {
		t.Fatalf("Build() returned error: %v", err)
	}
	if len(got.Edges) != 1 {
		t.Fatalf("expected 1 aggregated edge, got %d", len(got.Edges))
	}

	edge := got.Edges[0]
	if len(edge.EvidenceIDs) != 2 || edge.EvidenceIDs[0] != "evidence-a" || edge.EvidenceIDs[1] != "evidence-b" {
		t.Fatalf("unexpected evidence references: %v", edge.EvidenceIDs)
	}
	if len(edge.ObservationIDs) != 2 || edge.ObservationIDs[0] != "observation-a" || edge.ObservationIDs[1] != "observation-b" {
		t.Fatalf("unexpected observation references: %v", edge.ObservationIDs)
	}
	if err := got.Validate(); err != nil {
		t.Fatalf("generated graph is invalid: %v", err)
	}
}

func TestBuildIsDeterministic(t *testing.T) {
	records := []evidence.Evidence{
		{
			ID:       "evidence-b",
			EntityID: "b.example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.20",
		},
		{
			ID:       "evidence-a",
			EntityID: "a.example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.10",
		},
	}

	first, err := Build(records, nil)
	if err != nil {
		t.Fatalf("first Build() returned error: %v", err)
	}

	second, err := Build(records, nil)
	if err != nil {
		t.Fatalf("second Build() returned error: %v", err)
	}

	if len(first.Nodes) != len(second.Nodes) || len(first.Edges) != len(second.Edges) {
		t.Fatal("graph output sizes differ")
	}

	for i := range first.Nodes {
		if first.Nodes[i] != second.Nodes[i] {
			t.Fatalf("node order differs at index %d", i)
		}
	}

	for i := range first.Edges {
		a, b := first.Edges[i], second.Edges[i]
		if a.ID != b.ID || a.Source != b.Source || a.Target != b.Target {
			t.Fatalf("edge order differs at index %d", i)
		}
	}
}

func TestBuildRejectsEvidenceIDWithSurroundingWhitespace(t *testing.T) {
	records := []evidence.Evidence{
		{
			ID:       " evidence-1 ",
			EntityID: "example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.1",
		},
	}

	if _, err := Build(records, nil); err == nil {
		t.Fatal("expected error for evidence ID with surrounding whitespace")
	}
}

func TestBuildRejectsObservationIDWithSurroundingWhitespace(t *testing.T) {
	records := []evidence.Evidence{
		{
			ID:       "evidence-1",
			EntityID: "example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.1",
		},
	}
	observations := []evidence.Observation{
		{
			ID:         " observation-1 ",
			EvidenceID: "evidence-1",
			Source:     "test",
			ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			EventIDs:   []string{"event-1"},
		},
	}

	if _, err := Build(records, observations); err == nil {
		t.Fatal("expected error for observation ID with surrounding whitespace")
	}
}

func TestBuildRejectsObservationEvidenceIDWithSurroundingWhitespace(t *testing.T) {
	records := []evidence.Evidence{
		{
			ID:       "evidence-1",
			EntityID: "example.com",
			Type:     evidence.TypeDNSAddress,
			Value:    "192.0.2.1",
		},
	}
	observations := []evidence.Observation{
		{
			ID:         "observation-1",
			EvidenceID: " evidence-1 ",
			Source:     "test",
			ObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			EventIDs:   []string{"event-1"},
		},
	}

	if _, err := Build(records, observations); err == nil {
		t.Fatal("expected error for observation evidence ID with surrounding whitespace")
	}
}
