package evidence

import (
	"errors"
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
