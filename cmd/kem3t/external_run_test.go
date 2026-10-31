package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/externalintel"
	"github.com/itsFuRy007/kem3t/internal/history"
)

func TestRunExternalCollectionPersistsCompletedRunAndSnapshot(t *testing.T) {
	t.Parallel()

	snapshotDir := t.TempDir()
	target := "example.com"

	err := runExternalCollection(
		target,
		snapshotDir,
		"ct",
		5*time.Second,
		func(ctx context.Context, registry *evidence.Registry, target string) error {
			report := externalintel.CTReport{
				Target:      target,
				Source:      "test-ct",
				RetrievedAt: time.Now().UTC(),
				Records: []externalintel.CTRecord{
					{
						CertificateID: 101,
						DNSNames:      []string{"www.example.com"},
						IssuerName:    "Test Issuer",
					},
				},
			}

			added, err := externalintel.RegisterCTReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
			if err != nil {
				return err
			}
			if added != 1 {
				t.Fatalf("expected 1 new observation, got %d", added)
			}
			return nil
		},
	)
	if err != nil {
		t.Fatalf("runExternalCollection returned error: %v", err)
	}

	registry, err := evidence.OpenRegistry(filepath.Join(snapshotDir, "evidence.db"))
	if err != nil {
		t.Fatalf("open evidence registry: %v", err)
	}
	defer registry.Close()

	runs, err := registry.CollectionRuns(target)
	if err != nil {
		t.Fatalf("load collection runs: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("expected 1 collection run, got %d", len(runs))
	}
	if runs[0].Status != evidence.CollectionRunCompleted {
		t.Fatalf("expected completed run, got %q", runs[0].Status)
	}
	if runs[0].EventCount != 1 {
		t.Fatalf("expected event count 1, got %d", runs[0].EventCount)
	}
	if runs[0].FinishedAt.IsZero() {
		t.Fatal("expected run finish timestamp to be persisted")
	}

	store, err := history.NewStore(filepath.Join(snapshotDir, "history"))
	if err != nil {
		t.Fatalf("create history store: %v", err)
	}
	snapshots, err := store.List()
	if err != nil {
		t.Fatalf("list history snapshots: %v", err)
	}
	if len(snapshots) != 1 {
		t.Fatalf("expected 1 history snapshot, got %d", len(snapshots))
	}
	if snapshots[0].RunID != runs[0].ID {
		t.Fatalf("snapshot run ID %q does not match collection run %q", snapshots[0].RunID, runs[0].ID)
	}
	if snapshots[0].Collector != "investigation" {
		t.Fatalf("expected ct collector, got %q", snapshots[0].Collector)
	}
	if len(snapshots[0].Records) != 1 {
		t.Fatalf("expected 1 snapshot record, got %d", len(snapshots[0].Records))
	}
	if len(snapshots[0].Records[0].ObservationIDs) != 1 {
		t.Fatalf(
			"expected 1 observation reference, got %d",
			len(snapshots[0].Records[0].ObservationIDs),
		)
	}
}

func TestRunExternalCollectionRecordsFailureWithoutSnapshot(t *testing.T) {
	t.Parallel()

	snapshotDir := t.TempDir()
	expectedErr := errors.New("simulated provider failure")

	err := runExternalCollection(
		"example.com",
		snapshotDir,
		"ct",
		5*time.Second,
		func(ctx context.Context, registry *evidence.Registry, target string) error {
			return expectedErr
		},
	)
	if !errors.Is(err, expectedErr) {
		t.Fatalf("expected provider error, got %v", err)
	}

	registry, err := evidence.OpenRegistry(filepath.Join(snapshotDir, "evidence.db"))
	if err != nil {
		t.Fatalf("open evidence registry: %v", err)
	}
	defer registry.Close()

	runs, err := registry.CollectionRuns("example.com")
	if err != nil {
		t.Fatalf("load collection runs: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("expected 1 failed collection run, got %d", len(runs))
	}
	if runs[0].Status != evidence.CollectionRunFailed {
		t.Fatalf("expected failed status, got %q", runs[0].Status)
	}
	if runs[0].ErrorMessage == "" {
		t.Fatal("expected failure reason to be persisted")
	}

	store, err := history.NewStore(filepath.Join(snapshotDir, "history"))
	if err != nil {
		t.Fatalf("create history store: %v", err)
	}
	snapshots, err := store.List()
	if err != nil {
		t.Fatalf("list history snapshots: %v", err)
	}
	if len(snapshots) != 0 {
		t.Fatalf("expected no snapshot for failed run, got %d", len(snapshots))
	}
}

func TestRunExternalCollectionDoesNotReattributeOldObservations(t *testing.T) {
	t.Parallel()

	snapshotDir := t.TempDir()
	target := "example.com"
	retrievedAt := time.Time{}

	collect := func(ctx context.Context, registry *evidence.Registry, target string) error {
		if retrievedAt.IsZero() {
			retrievedAt = time.Now().UTC()
		}

		report := externalintel.CTReport{
			Target:      target,
			Source:      "test-ct",
			RetrievedAt: retrievedAt,
			Records: []externalintel.CTRecord{
				{
					CertificateID: 202,
					DNSNames:      []string{"api.example.com"},
					IssuerName:    "Test Issuer",
				},
			},
		}

		_, err := externalintel.RegisterCTReport(registry, report, evidence.ObservationProvenanceFromContext(ctx))
		return err
	}

	if err := runExternalCollection(target, snapshotDir, "ct", 5*time.Second, collect); err != nil {
		t.Fatalf("first collection run: %v", err)
	}
	if err := runExternalCollection(target, snapshotDir, "ct", 5*time.Second, collect); err != nil {
		t.Fatalf("second collection run: %v", err)
	}

	registry, err := evidence.OpenRegistry(filepath.Join(snapshotDir, "evidence.db"))
	if err != nil {
		t.Fatalf("open evidence registry: %v", err)
	}
	defer registry.Close()

	runs, err := registry.CollectionRuns(target)
	if err != nil {
		t.Fatalf("load collection runs: %v", err)
	}
	if len(runs) != 2 {
		t.Fatalf("expected 2 collection runs, got %d", len(runs))
	}

	for _, run := range runs {
		if run.Status != evidence.CollectionRunCompleted {
			t.Fatalf("expected completed run %q, got %q", run.ID, run.Status)
		}
	}

	var zeroEventRunID string
	for _, run := range runs {
		if run.EventCount == 0 {
			zeroEventRunID = run.ID
		}
	}
	if zeroEventRunID == "" {
		t.Fatal("expected the repeated run to contain zero new observations")
	}

	store, err := history.NewStore(filepath.Join(snapshotDir, "history"))
	if err != nil {
		t.Fatalf("create history store: %v", err)
	}
	snapshots, err := store.List()
	if err != nil {
		t.Fatalf("list history snapshots: %v", err)
	}
	if len(snapshots) != 2 {
		t.Fatalf("expected 2 history snapshots, got %d", len(snapshots))
	}

	for _, snapshot := range snapshots {
		if snapshot.RunID == zeroEventRunID && len(snapshot.Records) != 0 {
			t.Fatalf(
				"repeated run snapshot should be empty, but contains %d records",
				len(snapshot.Records),
			)
		}
	}
}

func TestRunExternalCollectionNormalizesTargetAndCountsNewDNSAddresses(t *testing.T) {
	t.Parallel()

	snapshotDir := t.TempDir()
	inputTarget := " HTTPS://Example.COM.:8443/path?q=1 "
	receivedTarget := ""

	err := runExternalCollection(
		inputTarget,
		snapshotDir,
		"ct",
		5*time.Second,
		func(ctx context.Context, registry *evidence.Registry, target string) error {
			receivedTarget = target
			return registry.AddEvidence(evidence.Evidence{
				ID:       "dns-address-1",
				EntityID: target,
				Type:     evidence.TypeDNSAddress,
				Value:    "192.0.2.10",
			})
		},
	)
	if err != nil {
		t.Fatalf("runExternalCollection returned error: %v", err)
	}

	if receivedTarget != "example.com" {
		t.Fatalf("collector received target %q, want %q", receivedTarget, "example.com")
	}

	registry, err := evidence.OpenRegistry(filepath.Join(snapshotDir, "evidence.db"))
	if err != nil {
		t.Fatalf("open evidence registry: %v", err)
	}
	defer registry.Close()

	runs, err := registry.CollectionRuns("example.com")
	if err != nil {
		t.Fatalf("load collection runs: %v", err)
	}
	if len(runs) != 1 {
		t.Fatalf("expected 1 collection run, got %d", len(runs))
	}
	if runs[0].Target != "example.com" {
		t.Fatalf("run target = %q, want %q", runs[0].Target, "example.com")
	}
	if runs[0].AddressCount != 1 {
		t.Fatalf("address count = %d, want 1", runs[0].AddressCount)
	}
	if runs[0].EventCount != 0 {
		t.Fatalf("event count = %d, want 0", runs[0].EventCount)
	}
}

func TestRunExternalCollectionMarksRunFailedWhenHistoryPersistenceFails(t *testing.T) {
	snapshotDir := t.TempDir()
	err := runExternalCollection("example.com", snapshotDir, "ct", 5*time.Second,
		func(context.Context, *evidence.Registry, string) error {
			return os.WriteFile(filepath.Join(snapshotDir, "history"), []byte("not a directory"), 0600)
		})
	if err == nil || !strings.Contains(err.Error(), "persist unified investigation history") {
		t.Fatalf("expected history persistence error, got %v", err)
	}
	registry, openErr := evidence.OpenRegistry(filepath.Join(snapshotDir, "evidence.db"))
	if openErr != nil {
		t.Fatalf("open evidence registry: %v", openErr)
	}
	defer registry.Close()
	runs, loadErr := registry.CollectionRuns("example.com")
	if loadErr != nil || len(runs) != 1 {
		t.Fatalf("expected one finalized collection run, got %+v, %v", runs, loadErr)
	}
	if runs[0].Status != evidence.CollectionRunFailed || !strings.Contains(runs[0].ErrorMessage, "persist external collection history snapshot") {
		t.Fatalf("history persistence failure was not reflected in run status: %+v", runs[0])
	}
}
