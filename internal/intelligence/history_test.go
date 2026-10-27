package intelligence

import (
	"reflect"
	"testing"
)

func TestCompareDNSHistory(t *testing.T) {
	previous := []string{
		"192.0.2.10",
		"192.0.2.11",
		"192.0.2.12",
	}

	current := []string{
		"192.0.2.11",
		"192.0.2.12",
		"192.0.2.13",
	}

	got, err := CompareDNSHistory("Example.COM", previous, current)
	if err != nil {
		t.Fatalf("CompareDNSHistory() error = %v", err)
	}

	if got.Target != "example.com" {
		t.Errorf("Target = %q, want example.com", got.Target)
	}

	if !reflect.DeepEqual(got.Added, []string{"192.0.2.13"}) {
		t.Errorf("Added = %v", got.Added)
	}

	if !reflect.DeepEqual(got.Removed, []string{"192.0.2.10"}) {
		t.Errorf("Removed = %v", got.Removed)
	}

	if !reflect.DeepEqual(
		got.Unchanged,
		[]string{"192.0.2.11", "192.0.2.12"},
	) {
		t.Errorf("Unchanged = %v", got.Unchanged)
	}

	if got.PreviousCount != 3 || got.CurrentCount != 3 {
		t.Errorf(
			"counts = previous:%d current:%d, want 3 and 3",
			got.PreviousCount,
			got.CurrentCount,
		)
	}
}

func TestCompareDNSHistoryNormalizesAndDeduplicates(t *testing.T) {
	got, err := CompareDNSHistory(
		" EXAMPLE.COM ",
		[]string{"192.0.2.10", "192.0.2.10"},
		[]string{"192.0.2.10"},
	)
	if err != nil {
		t.Fatalf("CompareDNSHistory() error = %v", err)
	}

	if got.PreviousCount != 1 || got.CurrentCount != 1 {
		t.Fatalf("unexpected unique counts: %+v", got)
	}

	if len(got.Added) != 0 || len(got.Removed) != 0 {
		t.Fatalf("unexpected changes: %+v", got)
	}

	if !reflect.DeepEqual(got.Unchanged, []string{"192.0.2.10"}) {
		t.Errorf("Unchanged = %v", got.Unchanged)
	}
}

func TestCompareDNSHistoryRejectsInvalidAddresses(t *testing.T) {
	_, err := CompareDNSHistory(
		"example.com",
		[]string{"not-an-ip"},
		[]string{"192.0.2.10"},
	)
	if err == nil {
		t.Fatal("expected invalid previous address to be rejected")
	}

	_, err = CompareDNSHistory(
		"example.com",
		nil,
		[]string{"not-an-ip"},
	)
	if err == nil {
		t.Fatal("expected invalid current address to be rejected")
	}
}

func TestCompareDNSHistoryRejectsEmptyTarget(t *testing.T) {
	_, err := CompareDNSHistory("", nil, nil)
	if err == nil {
		t.Fatal("expected empty target to be rejected")
	}
}
