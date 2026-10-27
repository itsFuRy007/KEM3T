package integration

import (
	"testing"

	"github.com/itsFuRy007/kem3t/internal/changes"
	"github.com/itsFuRy007/kem3t/internal/snapshots"
)

func TestDNSChangeWorkflow(t *testing.T) {
	store, err := snapshots.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("create snapshot store: %v", err)
	}

	previous, err := snapshots.New("Example.COM", []string{
		"192.0.2.10",
		"192.0.2.11",
	})
	if err != nil {
		t.Fatalf("create previous snapshot: %v", err)
	}

	if err := store.Save(previous); err != nil {
		t.Fatalf("save previous snapshot: %v", err)
	}

	loaded, err := store.Load("example.com")
	if err != nil {
		t.Fatalf("load previous snapshot: %v", err)
	}

	current, err := snapshots.New("example.com", []string{
		"192.0.2.10",
		"192.0.2.25",
	})
	if err != nil {
		t.Fatalf("create current snapshot: %v", err)
	}

	detector := changes.NewDetector()

	detected, err := detector.Compare(
		changes.Snapshot{
			Target:    loaded.Target,
			Addresses: loaded.Addresses,
		},
		changes.Snapshot{
			Target:    current.Target,
			Addresses: current.Addresses,
		},
	)
	if err != nil {
		t.Fatalf("compare snapshots: %v", err)
	}

	if len(detected) != 2 {
		t.Fatalf("expected 2 changes, got %d", len(detected))
	}

	expected := map[changes.ChangeType]string{
		changes.AddressAdded:   "192.0.2.25",
		changes.AddressRemoved: "192.0.2.11",
	}

	for _, change := range detected {
		address, ok := expected[change.Type]
		if !ok {
			t.Fatalf("unexpected change type: %s", change.Type)
		}

		if change.Address != address {
			t.Errorf(
				"unexpected address for %s: got %s, want %s",
				change.Type,
				change.Address,
				address,
			)
		}
	}
}
