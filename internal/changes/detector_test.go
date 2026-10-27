package changes

import (
	"reflect"
	"testing"
)

func TestCompareDetectsAddedAndRemovedAddresses(t *testing.T) {
	detector := NewDetector()

	previous := Snapshot{
		Target: "api.example.test",
		Addresses: []string{
			"192.0.2.10",
			"192.0.2.11",
		},
	}

	current := Snapshot{
		Target: "api.example.test",
		Addresses: []string{
			"192.0.2.10",
			"192.0.2.25",
		},
	}

	got, err := detector.Compare(previous, current)
	if err != nil {
		t.Fatalf("Compare() returned an error: %v", err)
	}

	want := []Change{
		{
			Target:  "api.example.test",
			Type:    AddressRemoved,
			Address: "192.0.2.11",
		},
		{
			Target:  "api.example.test",
			Type:    AddressAdded,
			Address: "192.0.2.25",
		},
	}

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Compare() = %#v, want %#v", got, want)
	}
}

func TestCompareReturnsNoChangesForIdenticalSnapshots(t *testing.T) {
	detector := NewDetector()

	snapshot := Snapshot{
		Target:    "api.example.test",
		Addresses: []string{"192.0.2.10"},
	}

	got, err := detector.Compare(snapshot, snapshot)
	if err != nil {
		t.Fatalf("Compare() returned an error: %v", err)
	}

	if len(got) != 0 {
		t.Errorf("got %d changes, want 0", len(got))
	}
}

func TestCompareRejectsDifferentTargets(t *testing.T) {
	detector := NewDetector()

	previous := Snapshot{
		Target:    "one.example.test",
		Addresses: []string{"192.0.2.10"},
	}

	current := Snapshot{
		Target:    "two.example.test",
		Addresses: []string{"192.0.2.11"},
	}

	if _, err := detector.Compare(previous, current); err == nil {
		t.Fatal("expected an error for different targets")
	}
}

func TestCompareRejectsInvalidAddress(t *testing.T) {
	detector := NewDetector()

	previous := Snapshot{
		Target:    "api.example.test",
		Addresses: []string{"not-an-ip"},
	}

	current := Snapshot{
		Target:    "api.example.test",
		Addresses: []string{"192.0.2.10"},
	}

	if _, err := detector.Compare(previous, current); err == nil {
		t.Fatal("expected an error for invalid IP address")
	}
}

func TestCompareIgnoresDuplicateAddresses(t *testing.T) {
	detector := NewDetector()

	previous := Snapshot{
		Target:    "api.example.test",
		Addresses: []string{"192.0.2.10", "192.0.2.10"},
	}

	current := Snapshot{
		Target:    "api.example.test",
		Addresses: []string{"192.0.2.10"},
	}

	got, err := detector.Compare(previous, current)
	if err != nil {
		t.Fatalf("Compare() returned an error: %v", err)
	}

	if len(got) != 0 {
		t.Errorf("got %d changes, want 0", len(got))
	}
}
