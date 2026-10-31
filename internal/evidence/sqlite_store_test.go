package evidence

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteRegistryPersistsEvidenceAndObservations(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "evidence.db")

	registry, err := OpenRegistry(dbPath)
	if err != nil {
		t.Fatalf("open registry: %v", err)
	}

	e := Evidence{
		ID:       "dns-address:example.com:192.0.2.10",
		EntityID: "example.com",
		Type:     TypeDNSAddress,
		Value:    "192.0.2.10",
	}

	if err := registry.AddEvidence(e); err != nil {
		_ = registry.Close()
		t.Fatalf("add evidence: %v", err)
	}

	observedAt := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	o := Observation{
		ID:         "observation:event-001",
		EvidenceID: e.ID,
		Source:     "dns",
		ObservedAt: observedAt,
		EventIDs:   []string{"event-001"},
	}

	if err := registry.AddObservation(o); err != nil {
		_ = registry.Close()
		t.Fatalf("add observation: %v", err)
	}

	if err := registry.Close(); err != nil {
		t.Fatalf("close registry: %v", err)
	}

	reopened, err := OpenRegistry(dbPath)
	if err != nil {
		t.Fatalf("reopen registry: %v", err)
	}
	defer reopened.Close()

	gotEvidence, err := reopened.GetEvidence(e.ID)
	if err != nil {
		t.Fatalf("get persisted evidence: %v", err)
	}
	if gotEvidence != e {
		t.Fatalf("evidence mismatch: got %+v, want %+v", gotEvidence, e)
	}

	gotObservation, err := reopened.GetObservation(o.ID)
	if err != nil {
		t.Fatalf("get persisted observation: %v", err)
	}
	if gotObservation.ID != o.ID ||
		gotObservation.EvidenceID != o.EvidenceID ||
		gotObservation.Source != o.Source ||
		!gotObservation.ObservedAt.Equal(o.ObservedAt) ||
		len(gotObservation.EventIDs) != 1 ||
		gotObservation.EventIDs[0] != "event-001" {
		t.Fatalf("observation mismatch: got %+v, want %+v", gotObservation, o)
	}

	history, err := reopened.ObservationsForEvidence(e.ID)
	if err != nil {
		t.Fatalf("get observation history: %v", err)
	}
	if len(history) != 1 || history[0].ID != o.ID {
		t.Fatalf("unexpected observation history: %+v", history)
	}
}

func TestSQLiteRegistryRejectsDuplicateRecords(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "evidence.db")

	registry, err := OpenRegistry(dbPath)
	if err != nil {
		t.Fatalf("open registry: %v", err)
	}
	defer registry.Close()

	e := Evidence{
		ID:       "dns-address:example.com:192.0.2.20",
		EntityID: "example.com",
		Type:     TypeDNSAddress,
		Value:    "192.0.2.20",
	}

	if err := registry.AddEvidence(e); err != nil {
		t.Fatalf("add evidence: %v", err)
	}
	if err := registry.AddEvidence(e); !errors.Is(err, ErrEvidenceExists) {
		t.Fatalf("expected ErrEvidenceExists, got %v", err)
	}

	o := Observation{
		ID:         "observation:event-002",
		EvidenceID: e.ID,
		Source:     "dns",
		ObservedAt: time.Date(2026, 10, 27, 11, 0, 0, 0, time.UTC),
		EventIDs:   []string{"event-002"},
	}

	if err := registry.AddObservation(o); err != nil {
		t.Fatalf("add observation: %v", err)
	}
	if err := registry.AddObservation(o); !errors.Is(err, ErrObservationExists) {
		t.Fatalf("expected ErrObservationExists, got %v", err)
	}
}

func TestSQLiteSaveBatchPersistsEvidenceAndObservations(t *testing.T) {
	store, err := OpenSQLiteStore(filepath.Join(t.TempDir(), "batch.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	first := validEvidence()
	second := validEvidence()
	second.ID = "dns-address:example.com:192.0.2.11"
	second.Value = "192.0.2.11"
	firstObservation := validObservation()
	secondObservation := validObservation()
	secondObservation.ID = "batch-observation-2"
	secondObservation.EvidenceID = second.ID
	if err := store.SaveBatch(context.Background(), []Evidence{first, second}, []Observation{firstObservation, secondObservation}); err != nil {
		t.Fatal(err)
	}
	records, observations, err := store.LoadAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || len(observations) != 2 {
		t.Fatalf("batch persisted %d evidence and %d observations, want 2 each", len(records), len(observations))
	}
}

func TestSQLiteSaveBatchRollsBackEvidenceWhenObservationInsertFails(t *testing.T) {
	store, err := OpenSQLiteStore(filepath.Join(t.TempDir(), "rollback.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	existing := validEvidence()
	if err := store.SaveEvidence(context.Background(), existing); err != nil {
		t.Fatal(err)
	}
	existingObservation := validObservation()
	if err := store.SaveObservation(context.Background(), existingObservation); err != nil {
		t.Fatal(err)
	}
	newItem := validEvidence()
	newItem.ID = "new-evidence"
	duplicateObservation := validObservation()
	duplicateObservation.EvidenceID = newItem.ID
	if err := store.SaveBatch(context.Background(), []Evidence{newItem}, []Observation{duplicateObservation}); !errors.Is(err, ErrObservationExists) {
		t.Fatalf("expected ErrObservationExists, got %v", err)
	}
	records, observations, err := store.LoadAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].ID != existing.ID || len(observations) != 1 {
		t.Fatalf("failed batch was not rolled back: evidence=%+v observations=%+v", records, observations)
	}
}

func TestSQLiteSaveBatchRollsBackOnMissingEvidenceReference(t *testing.T) {
	store, err := OpenSQLiteStore(filepath.Join(t.TempDir(), "missing-reference.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	newItem := validEvidence()
	observation := validObservation()
	observation.EvidenceID = "not-in-batch-or-database"
	if err := store.SaveBatch(context.Background(), []Evidence{newItem}, []Observation{observation}); !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatalf("expected ErrEvidenceNotFound, got %v", err)
	}
	records, observations, err := store.LoadAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 0 || len(observations) != 0 {
		t.Fatalf("foreign-key failure did not roll back batch: evidence=%+v observations=%+v", records, observations)
	}
}

func TestSQLiteRegistryAddBatchSurvivesReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "registry-batch.db")
	registry, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	first := validEvidence()
	second := validEvidence()
	second.ID = "dns-address:example.com:192.0.2.12"
	second.Value = "192.0.2.12"
	firstObservation := validObservation()
	secondObservation := validObservation()
	secondObservation.ID = "registry-batch-observation-2"
	secondObservation.EvidenceID = second.ID
	if err := registry.AddBatch(context.Background(), []Evidence{first, second}, []Observation{firstObservation, secondObservation}); err != nil {
		_ = registry.Close()
		t.Fatal(err)
	}
	if err := registry.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenRegistry(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if len(reopened.AllEvidence()) != 2 || len(reopened.AllObservations()) != 2 {
		t.Fatalf("reopened registry lost batch records")
	}
	if _, err := reopened.ObservationsForEvidence(second.ID); err != nil {
		t.Fatalf("reopened batch evidence history unavailable: %v", err)
	}
}

func TestSQLiteSaveBatchRollsBackOnDuplicateEvidence(t *testing.T) {
	store, err := OpenSQLiteStore(filepath.Join(t.TempDir(), "duplicate-evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	existing := validEvidence()
	if err := store.SaveEvidence(context.Background(), existing); err != nil {
		t.Fatal(err)
	}
	newItem := validEvidence()
	newItem.ID = "new-evidence-before-duplicate"
	if err := store.SaveBatch(context.Background(), []Evidence{newItem, existing}, nil); !errors.Is(err, ErrEvidenceExists) {
		t.Fatalf("expected ErrEvidenceExists, got %v", err)
	}
	records, observations, err := store.LoadAll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].ID != existing.ID || len(observations) != 0 {
		t.Fatalf("duplicate evidence batch was not rolled back: evidence=%+v observations=%+v", records, observations)
	}
}
