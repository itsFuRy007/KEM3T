package evidence

import (
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectionRunPersistsAcrossReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "evidence.db")
	started := time.Now().UTC().Truncate(time.Nanosecond)

	registry, err := OpenRegistry(dbPath)
	if err != nil {
		t.Fatalf("open registry: %v", err)
	}

	run := CollectionRun{
		ID:        "run-test-001",
		Target:    "Example.COM",
		StartedAt: started,
		Status:    CollectionRunRunning,
	}

	if err := registry.AddCollectionRun(run); err != nil {
		t.Fatalf("add collection run: %v", err)
	}

	run.Status = CollectionRunCompleted
	run.FinishedAt = started.Add(2 * time.Second)
	run.EventCount = 5
	run.AddressCount = 2

	if err := registry.UpdateCollectionRun(run); err != nil {
		t.Fatalf("update collection run: %v", err)
	}

	if err := registry.Close(); err != nil {
		t.Fatalf("close registry: %v", err)
	}

	registry, err = OpenRegistry(dbPath)
	if err != nil {
		t.Fatalf("reopen registry: %v", err)
	}
	defer registry.Close()

	got, err := registry.GetCollectionRun(run.ID)
	if err != nil {
		t.Fatalf("get collection run: %v", err)
	}

	if got.Target != "example.com" {
		t.Errorf("target = %q, want example.com", got.Target)
	}
	if got.Status != CollectionRunCompleted {
		t.Errorf("status = %q, want completed", got.Status)
	}
	if got.EventCount != 5 {
		t.Errorf("event count = %d, want 5", got.EventCount)
	}
	if got.AddressCount != 2 {
		t.Errorf("address count = %d, want 2", got.AddressCount)
	}
	if !got.FinishedAt.Equal(run.FinishedAt) {
		t.Errorf("finish time = %v, want %v", got.FinishedAt, run.FinishedAt)
	}

	runs, err := registry.CollectionRuns("EXAMPLE.COM")
	if err != nil {
		t.Fatalf("list collection runs: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("got %d runs, want 1", len(runs))
	}
}

func TestCollectionRunRejectsInvalidTransitions(t *testing.T) {
	registry := NewRegistry()

	started := time.Now().UTC()
	run := CollectionRun{
		ID:        "run-invalid",
		Target:    "example.com",
		StartedAt: started,
		Status:    CollectionRunRunning,
	}

	if err := registry.AddCollectionRun(run); err != nil {
		t.Fatalf("add running run: %v", err)
	}

	invalid := run
	invalid.Status = CollectionRunCompleted
	// A completed run must have a finish time.
	if err := registry.UpdateCollectionRun(invalid); err == nil {
		t.Fatal("expected invalid completed run to be rejected")
	}

	missing := CollectionRun{
		ID:        "missing-run",
		Target:    "example.com",
		StartedAt: started,
		Status:    CollectionRunRunning,
	}
	if err := registry.UpdateCollectionRun(missing); err == nil {
		t.Fatal("expected update of missing run to fail")
	}

	if _, err := registry.GetCollectionRun("missing-run"); err == nil {
		t.Fatal("expected missing run lookup to fail")
	}
}

func TestCollectionRunFailureIsPersisted(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "evidence.db")
	registry, err := OpenRegistry(dbPath)
	if err != nil {
		t.Fatalf("open registry: %v", err)
	}

	started := time.Now().UTC()
	run := CollectionRun{
		ID:        "run-failed",
		Target:    "example.com",
		StartedAt: started,
		Status:    CollectionRunRunning,
	}
	if err := registry.AddCollectionRun(run); err != nil {
		t.Fatalf("add run: %v", err)
	}

	run.Status = CollectionRunFailed
	run.FinishedAt = started.Add(time.Second)
	run.ErrorMessage = "simulated collector failure"

	if err := registry.UpdateCollectionRun(run); err != nil {
		t.Fatalf("update failed run: %v", err)
	}
	if err := registry.Close(); err != nil {
		t.Fatalf("close registry: %v", err)
	}

	registry, err = OpenRegistry(dbPath)
	if err != nil {
		t.Fatalf("reopen registry: %v", err)
	}
	defer registry.Close()

	got, err := registry.GetCollectionRun(run.ID)
	if err != nil {
		t.Fatalf("get failed run: %v", err)
	}
	if got.Status != CollectionRunFailed {
		t.Fatalf("status = %q, want failed", got.Status)
	}
	if got.ErrorMessage != run.ErrorMessage {
		t.Fatalf("error message = %q, want %q", got.ErrorMessage, run.ErrorMessage)
	}

	// Keep errors imported and verify the registry returns ordinary errors
	// for unknown IDs without changing the stored history.
	_, err = registry.GetCollectionRun("unknown")
	if err == nil || errors.Is(err, ErrEvidenceNotFound) {
		t.Fatalf("expected a collection-run lookup error, got %v", err)
	}
}
