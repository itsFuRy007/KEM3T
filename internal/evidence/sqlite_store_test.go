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

func TestSQLiteStoreSaveBatchPersistsEvidenceAndObservationsAtomically(t *testing.T) {
	store, err := OpenSQLiteStore(filepath.Join(t.TempDir(), "batch.db"))
	if err != nil { t.Fatal(err) }
	defer store.Close()
	ctx := context.Background()
	evidenceRecords := []Evidence{
		{ID:"batch-e1", EntityID:"example.com", Type:TypeDNSAddress, Value:"192.0.2.1"},
		{ID:"batch-e2", EntityID:"example.com", Type:TypeDNSAddress, Value:"192.0.2.2"},
	}
	observations := []Observation{
		{ID:"batch-o1", EvidenceID:"batch-e1", Source:"dns", ObservedAt:time.Date(2026,10,29,12,0,0,0,time.UTC), EventIDs:[]string{"event-1"}},
		{ID:"batch-o2", EvidenceID:"batch-e2", Source:"dns", ObservedAt:time.Date(2026,10,29,12,1,0,0,time.UTC), EventIDs:[]string{"event-2"}},
	}
	if err := store.SaveBatch(ctx, evidenceRecords, observations); err != nil { t.Fatalf("save batch: %v", err) }
	for _, record := range evidenceRecords {
		if _, err := store.LoadEvidence(ctx, record.ID); err != nil { t.Errorf("load evidence %s: %v", record.ID, err) }
	}
	for _, record := range observations {
		if _, err := store.LoadObservation(ctx, record.ID); err != nil { t.Errorf("load observation %s: %v", record.ID, err) }
	}
}

func TestSQLiteStoreSaveBatchRollsBackOnFailure(t *testing.T) {
	store, err := OpenSQLiteStore(filepath.Join(t.TempDir(), "rollback.db"))
	if err != nil { t.Fatal(err) }
	defer store.Close()
	ctx := context.Background()
	err = store.SaveBatch(ctx,
		[]Evidence{
			{ID:"rollback-e1", EntityID:"example.com", Type:TypeDNSAddress, Value:"192.0.2.1"},
			{ID:"rollback-e1", EntityID:"example.com", Type:TypeDNSAddress, Value:"192.0.2.2"},
		}, nil)
	if !errors.Is(err, ErrEvidenceExists) { t.Fatalf("expected duplicate evidence error, got %v", err) }
	if _, err := store.LoadEvidence(ctx, "rollback-e1"); !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatalf("failed batch left partial evidence behind: %v", err)
	}
	err = store.SaveBatch(ctx,
		[]Evidence{{ID:"rollback-e2", EntityID:"example.com", Type:TypeDNSAddress, Value:"192.0.2.3"}},
		[]Observation{{ID:"rollback-o1", EvidenceID:"missing-evidence", Source:"dns", ObservedAt:time.Now().UTC(), EventIDs:[]string{"event-x"}}})
	if !errors.Is(err, ErrEvidenceNotFound) { t.Fatalf("expected missing evidence error, got %v", err) }
	if _, err := store.LoadEvidence(ctx, "rollback-e2"); !errors.Is(err, ErrEvidenceNotFound) {
		t.Fatalf("observation failure did not roll back evidence: %v", err)
	}
}
