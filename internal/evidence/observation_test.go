package evidence

import (
	"testing"
	"time"
)

func validObservation() Observation {
	return Observation{
		ID:         "obs-001",
		EvidenceID: "ev-001",
		Source:     "dns-collector",
		ObservedAt: time.Date(2026, 10, 27, 0, 0, 0, 0, time.UTC),
		EventIDs:   []string{"dns-001"},
	}
}

func TestObservationValidate(t *testing.T) {
	if err := validObservation().Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestObservationValidateRejectsInvalidFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Observation)
	}{
		{"missing ID", func(o *Observation) { o.ID = "" }},
		{"missing evidence ID", func(o *Observation) { o.EvidenceID = "" }},
		{"missing source", func(o *Observation) { o.Source = "" }},
		{"missing timestamp", func(o *Observation) { o.ObservedAt = time.Time{} }},
		{"missing event IDs", func(o *Observation) { o.EventIDs = nil }},
		{"empty event ID", func(o *Observation) { o.EventIDs = []string{""} }},
		{"duplicate event IDs", func(o *Observation) {
			o.EventIDs = []string{"dns-001", "dns-001"}
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := validObservation()
			tt.mutate(&o)

			if err := o.Validate(); err == nil {
				t.Fatal("Validate() expected an error")
			}
		})
	}
}
