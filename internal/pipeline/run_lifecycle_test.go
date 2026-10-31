package pipeline

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

func TestFinalizeCollectionRunMarksHistoryFailureAsFailed(t *testing.T) {
	snapshotDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(snapshotDir, "history"), []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	registry, err := evidence.OpenRegistry(filepath.Join(snapshotDir, "evidence.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer registry.Close()

	now := time.Now().UTC()
	run := evidence.CollectionRun{
		ID:         "http-test-run",
		Target:     "example.com",
		StartedAt:  now.Add(-time.Second),
		FinishedAt: now,
		Status:     evidence.CollectionRunCompleted,
	}
	if err := registry.AddCollectionRun(run); err != nil {
		t.Fatal(err)
	}

	var retErr error
	finalizeCollectionRun(snapshotDir, registry, &run, nil, &retErr)
	if retErr == nil || !strings.Contains(retErr.Error(), "persist history snapshot") {
		t.Fatalf("expected history persistence error, got %v", retErr)
	}
	runs, err := registry.CollectionRuns("example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 {
		t.Fatalf("got %d collection runs, want 1", len(runs))
	}
	if runs[0].Status != evidence.CollectionRunFailed ||
		!strings.Contains(runs[0].ErrorMessage, "persist history snapshot") {
		t.Fatalf("run did not retain failed history state: %+v", runs[0])
	}
}
