package evidence

import (
	"context"
	"errors"
	"testing"
)

func TestRegistryAddBatchUniqueSkipsExactDuplicatesAndAddsNewRecords(t *testing.T) {
	registry := NewRegistry()
	first := validEvidence()
	firstObservation := validObservation()
	if err := registry.AddEvidence(first); err != nil {
		t.Fatal(err)
	}
	if err := registry.AddObservation(firstObservation); err != nil {
		t.Fatal(err)
	}

	second := validEvidence()
	second.ID = "dns-address:example.com:192.0.2.11"
	second.Value = "192.0.2.11"
	secondObservation := validObservation()
	secondObservation.ID = "observation-batch-unique-2"
	secondObservation.EvidenceID = second.ID

	evidenceCount, observationCount, err := registry.AddBatchUnique(
		context.Background(),
		[]Evidence{first, second, second},
		[]Observation{firstObservation, secondObservation, secondObservation},
	)
	if err != nil {
		t.Fatal(err)
	}
	if evidenceCount != 1 || observationCount != 1 {
		t.Fatalf("added counts = %d evidence, %d observations; want 1 each", evidenceCount, observationCount)
	}
	if len(registry.AllEvidence()) != 2 || len(registry.AllObservations()) != 2 {
		t.Fatalf("unexpected registry contents: evidence=%d observations=%d", len(registry.AllEvidence()), len(registry.AllObservations()))
	}
}

func TestRegistryAddBatchUniqueRejectsConflictingDuplicateIDAtomically(t *testing.T) {
	registry := NewRegistry()
	first := validEvidence()
	if err := registry.AddEvidence(first); err != nil {
		t.Fatal(err)
	}
	conflict := first
	conflict.Value = "192.0.2.99"
	newItem := validEvidence()
	newItem.ID = "new-evidence-that-must-not-be-added"

	if _, _, err := registry.AddBatchUnique(context.Background(), []Evidence{newItem, conflict}, nil); !errors.Is(err, ErrEvidenceExists) {
		t.Fatalf("expected conflicting duplicate to be rejected, got %v", err)
	}
	if len(registry.AllEvidence()) != 1 {
		t.Fatalf("conflicting batch partially modified registry: %+v", registry.AllEvidence())
	}
}
