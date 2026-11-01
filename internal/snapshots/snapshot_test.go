package snapshots

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestNewNormalizesSnapshot(t *testing.T) {
	snapshot, err := New(" API.Example.Test ", []string{
		"192.0.2.11",
		"192.0.2.10",
		"192.0.2.11",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if snapshot.Target != "api.example.test" {
		t.Errorf("Target = %q", snapshot.Target)
	}

	want := []string{"192.0.2.10", "192.0.2.11"}
	if !reflect.DeepEqual(snapshot.Addresses, want) {
		t.Errorf("Addresses = %v, want %v", snapshot.Addresses, want)
	}

	if snapshot.Collected.IsZero() {
		t.Fatal("Collected timestamp must be set")
	}
}

func TestStoreSaveAndLoad(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "snapshots"))
	if err != nil {
		t.Fatal(err)
	}

	original, err := New("api.example.test", []string{
		"192.0.2.10",
		"2001:db8::1",
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := store.Save(original); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	loaded, err := store.Load("API.EXAMPLE.TEST")
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if loaded.Target != original.Target {
		t.Errorf("Target = %q, want %q", loaded.Target, original.Target)
	}
	if !loaded.Collected.Equal(original.Collected) {
		t.Errorf("Collected = %v, want %v", loaded.Collected, original.Collected)
	}
	if !reflect.DeepEqual(loaded.Addresses, original.Addresses) {
		t.Errorf("Addresses = %v, want %v", loaded.Addresses, original.Addresses)
	}
}

func TestStoreRejectsInvalidSnapshot(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	snapshot := Snapshot{
		Target:    "api.example.test",
		Collected: time.Now().UTC(),
		Addresses: []string{"not-an-ip"},
	}

	if err := store.Save(snapshot); err == nil {
		t.Fatal("Save() expected an error for invalid IP")
	}
}

func TestLoadRejectsCorruptedJSON(t *testing.T) {
	dir := t.TempDir()
	store, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(dir, "api.example.test.json")
	if err := os.WriteFile(path, []byte("{invalid"), 0600); err != nil {
		t.Fatal(err)
	}

	if _, err := store.Load("api.example.test"); err == nil {
		t.Fatal("Load() expected an error for corrupted JSON")
	}
}

func TestStoreReplacesPreviousSnapshot(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	first, err := New("api.example.test", []string{"192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(first); err != nil {
		t.Fatal(err)
	}

	second, err := New("api.example.test", []string{"192.0.2.25"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(second); err != nil {
		t.Fatal(err)
	}

	loaded, err := store.Load("api.example.test")
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(loaded.Addresses, second.Addresses) {
		t.Errorf("Addresses = %v, want %v", loaded.Addresses, second.Addresses)
	}
}

func TestStoreRejectsEmptyDirectory(t *testing.T) {
	if _, err := NewStore(" "); err == nil {
		t.Fatal("NewStore() expected an error for empty directory")
	}
}

func TestSnapshotValidationRejectsUnsortedAddresses(t *testing.T) {
	snapshot := Snapshot{
		Target:    "api.example.test",
		Collected: time.Now().UTC(),
		Addresses: []string{"192.0.2.11", "192.0.2.10"},
	}

	err := snapshot.Validate()
	if err == nil || !strings.Contains(err.Error(), "sorted") {
		t.Fatalf("Validate() error = %v, want sorted-address error", err)
	}
}

func TestStoreRejectsUnsafeSnapshotTargets(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"../outside", "nested/target", "nested\\\\target", ".."} {
		t.Run(target, func(t *testing.T) {
			if _, err := New(target, nil); err == nil {
				t.Fatalf("New accepted unsafe target %q", target)
			}
			if _, err := store.Load(target); err == nil {
				t.Fatalf("Load accepted unsafe target %q", target)
			}
		})
	}
}
