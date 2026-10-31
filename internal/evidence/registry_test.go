package evidence

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestRegistryAddAndGetEvidence(t *testing.T) {
	r := NewRegistry()
	e := validEvidence()

	if err := r.AddEvidence(e); err != nil {
		t.Fatalf("AddEvidence() error = %v", err)
	}

	got, err := r.GetEvidence(e.ID)
	if err != nil {
		t.Fatalf("GetEvidence() error = %v", err)
	}

	if got != e {
		t.Fatalf("GetEvidence() = %#v, want %#v", got, e)
	}
}

func TestRegistryRejectsDuplicateEvidence(t *testing.T) {
	r := NewRegistry()
	e := validEvidence()

	if err := r.AddEvidence(e); err != nil {
		t.Fatal(err)
	}

	if err := r.AddEvidence(e); !errors.Is(err, ErrEvidenceExists) {
		t.Fatalf("AddEvidence() error = %v, want ErrEvidenceExists", err)
	}
}

func TestRegistryAddObservationAndGetHistory(t *testing.T) {
	r := NewRegistry()
	e := validEvidence()

	if err := r.AddEvidence(e); err != nil {
		t.Fatal(err)
	}

	first := validObservation()
	first.ID = "obs-002"
	first.ObservedAt = time.Date(2026, 10, 27, 2, 0, 0, 0, time.UTC)

	second := validObservation()
	second.ID = "obs-001"
	second.ObservedAt = time.Date(2026, 10, 27, 1, 0, 0, 0, time.UTC)

	if err := r.AddObservation(first); err != nil {
		t.Fatal(err)
	}

	if err := r.AddObservation(second); err != nil {
		t.Fatal(err)
	}

	history, err := r.ObservationsForEvidence(e.ID)
	if err != nil {
		t.Fatal(err)
	}

	if len(history) != 2 {
		t.Fatalf("history length = %d, want 2", len(history))
	}

	if history[0].ID != "obs-001" || history[1].ID != "obs-002" {
		t.Fatalf("history order = [%s, %s], want [obs-001, obs-002]",
			history[0].ID, history[1].ID)
	}
}

func TestRegistryRejectsObservationWithoutEvidence(t *testing.T) {
	r := NewRegistry()

	err := r.AddObservation(validObservation())
	if !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatalf("AddObservation() error = %v, want ErrEvidenceNotFound", err)
	}
}

func TestRegistryRejectsDuplicateObservation(t *testing.T) {
	r := NewRegistry()

	if err := r.AddEvidence(validEvidence()); err != nil {
		t.Fatal(err)
	}

	o := validObservation()
	if err := r.AddObservation(o); err != nil {
		t.Fatal(err)
	}

	if err := r.AddObservation(o); !errors.Is(err, ErrObservationExists) {
		t.Fatalf("AddObservation() error = %v, want ErrObservationExists", err)
	}
}

func TestRegistryGetMissingEvidence(t *testing.T) {
	r := NewRegistry()

	if _, err := r.GetEvidence("missing"); !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatalf("GetEvidence() error = %v, want ErrEvidenceNotFound", err)
	}
}

func TestRegistryGetMissingObservation(t *testing.T) {
	r := NewRegistry()

	if _, err := r.GetObservation("missing"); !errors.Is(err, ErrObservationNotFound) {
		t.Fatalf("GetObservation() error = %v, want ErrObservationNotFound", err)
	}
}
func TestRegistryAddObservationDoesNotModifyCallerSlice(t *testing.T) {
	r := NewRegistry()

	if err := r.AddEvidence(validEvidence()); err != nil {
		t.Fatal(err)
	}

	o := validObservation()
	o.EventIDs = []string{" dns-001 "}

	if err := r.AddObservation(o); err != nil {
		t.Fatalf("AddObservation() error = %v", err)
	}

	if o.EventIDs[0] != " dns-001 " {
		t.Fatalf(
			"AddObservation() modified caller's EventIDs: %q",
			o.EventIDs[0],
		)
	}

	stored, err := r.GetObservation(o.ID)
	if err != nil {
		t.Fatalf("GetObservation() error = %v", err)
	}

	if stored.EventIDs[0] != "dns-001" {
		t.Fatalf(
			"stored EventIDs[0] = %q, want %q",
			stored.EventIDs[0],
			"dns-001",
		)
	}
}

func TestClosedRegistryRejectsWritesAndKeepsRecordsReadable(t *testing.T) {
	registry, err := OpenRegistry(filepath.Join(t.TempDir(), "evidence.db"))
	if err != nil {
		t.Fatalf("open registry: %v", err)
	}

	started := time.Now().UTC()
	e := Evidence{
		ID:       "dns-address:example.com:192.0.2.10",
		EntityID: "example.com",
		Type:     TypeDNSAddress,
		Value:    "192.0.2.10",
	}
	if err := registry.AddEvidence(e); err != nil {
		t.Fatalf("add evidence: %v", err)
	}

	observation := Observation{
		ID:         "observation-before-close",
		EvidenceID: e.ID,
		Source:     "test",
		ObservedAt: started,
		EventIDs:   []string{"event-before-close"},
	}
	if err := registry.AddObservation(observation); err != nil {
		t.Fatalf("add observation: %v", err)
	}

	run := CollectionRun{
		ID:        "run-before-close",
		Target:    "example.com",
		StartedAt: started,
		Status:    CollectionRunRunning,
	}
	if err := registry.AddCollectionRun(run); err != nil {
		t.Fatalf("add collection run: %v", err)
	}

	if err := registry.Close(); err != nil {
		t.Fatalf("close registry: %v", err)
	}

	if _, err := registry.GetEvidence(e.ID); err != nil {
		t.Fatalf("read evidence after close: %v", err)
	}

	newEvidence := Evidence{
		ID:       "dns-address:example.com:192.0.2.11",
		EntityID: "example.com",
		Type:     TypeDNSAddress,
		Value:    "192.0.2.11",
	}
	if err := registry.AddEvidence(newEvidence); !errors.Is(err, ErrRegistryClosed) {
		t.Errorf("AddEvidence() error = %v, want ErrRegistryClosed", err)
	}

	newObservation := Observation{
		ID:         "observation-after-close",
		EvidenceID: e.ID,
		Source:     "test",
		ObservedAt: started.Add(time.Second),
		EventIDs:   []string{"event-after-close"},
	}
	if err := registry.AddObservation(newObservation); !errors.Is(err, ErrRegistryClosed) {
		t.Errorf("AddObservation() error = %v, want ErrRegistryClosed", err)
	}

	newRun := CollectionRun{
		ID:        "run-after-close",
		Target:    "example.com",
		StartedAt: started.Add(time.Second),
		Status:    CollectionRunRunning,
	}
	if err := registry.AddCollectionRun(newRun); !errors.Is(err, ErrRegistryClosed) {
		t.Errorf("AddCollectionRun() error = %v, want ErrRegistryClosed", err)
	}

	updatedRun := run
	updatedRun.Status = CollectionRunCompleted
	updatedRun.FinishedAt = started.Add(time.Second)
	if err := registry.UpdateCollectionRun(updatedRun); !errors.Is(err, ErrRegistryClosed) {
		t.Errorf("UpdateCollectionRun() error = %v, want ErrRegistryClosed", err)
	}

	if err := registry.Close(); err != nil {
		t.Errorf("second Close() error = %v", err)
	}
}

func TestRegistryAddBatchIsAtomicAndPreservesNormalizedRecords(t *testing.T) {
	registry := NewRegistry()
	first := validEvidence()
	second := validEvidence()
	second.ID = "dns-address:example.com:192.0.2.11"
	second.Value = " 192.0.2.11 "
	firstObservation := validObservation()
	secondObservation := validObservation()
	secondObservation.ID = "observation-2"
	secondObservation.EvidenceID = second.ID
	secondObservation.EventIDs = []string{" event-2 "}
	if err := registry.AddBatch(context.Background(), []Evidence{first, second}, []Observation{firstObservation, secondObservation}); err != nil {
		t.Fatal(err)
	}
	if len(registry.AllEvidence()) != 2 || len(registry.AllObservations()) != 2 {
		t.Fatalf("batch not fully registered")
	}
	got, err := registry.GetEvidence(second.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Value != "192.0.2.11" {
		t.Fatalf("DNS address was not normalized: %q", got.Value)
	}
	gotObservation, err := registry.GetObservation(secondObservation.ID)
	if err != nil {
		t.Fatal(err)
	}
	if gotObservation.EventIDs[0] != "event-2" {
		t.Fatalf("event reference was not normalized: %q", gotObservation.EventIDs[0])
	}
}

func TestRegistryAddBatchDoesNotPartiallyMutateOnValidationFailure(t *testing.T) {
	registry := NewRegistry()
	valid := validEvidence()
	invalid := validEvidence()
	invalid.ID = "invalid-evidence"
	invalid.Value = "not-an-ip"
	err := registry.AddBatch(context.Background(), []Evidence{valid, invalid}, nil)
	if err == nil {
		t.Fatal("expected invalid evidence to reject batch")
	}
	if len(registry.AllEvidence()) != 0 || len(registry.AllObservations()) != 0 {
		t.Fatal("failed batch partially changed registry")
	}
}

func TestRegistryAddBatchRejectsMissingReferencesAtomically(t *testing.T) {
	registry := NewRegistry()
	item := validEvidence()
	observation := validObservation()
	observation.EvidenceID = "missing-evidence"
	err := registry.AddBatch(context.Background(), []Evidence{item}, []Observation{observation})
	if !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatalf("expected ErrEvidenceNotFound, got %v", err)
	}
	if len(registry.AllEvidence()) != 0 || len(registry.AllObservations()) != 0 {
		t.Fatal("missing reference partially changed registry")
	}
}

func TestRegistryAddBatchHonorsCanceledContext(t *testing.T) {
	registry := NewRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := registry.AddBatch(ctx, []Evidence{validEvidence()}, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if len(registry.AllEvidence()) != 0 {
		t.Fatal("canceled batch changed registry")
	}
}

func TestRegistryAddBatchRejectsDuplicateIDsWithinBatch(t *testing.T) {
	registry := NewRegistry()
	item := validEvidence()
	err := registry.AddBatch(context.Background(), []Evidence{item, item}, nil)
	if !errors.Is(err, ErrEvidenceExists) {
		t.Fatalf("expected ErrEvidenceExists, got %v", err)
	}
	if len(registry.AllEvidence()) != 0 {
		t.Fatal("duplicate batch changed registry")
	}
}
