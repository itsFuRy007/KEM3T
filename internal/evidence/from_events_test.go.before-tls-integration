package evidence

import (
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

func TestFromDNSEvent(t *testing.T) {
	event := events.Event{
		ID:        "dns-001",
		Type:      events.EventDNSRecordFound,
		Timestamp: time.Date(2026, 10, 27, 1, 0, 0, 0, time.UTC),
		Target:    "API.Example.com",
		Source:    "dns-collector",
		Data: map[string]string{
			"record_type": "IP_ADDRESS",
			"value":       "192.0.2.10",
		},
	}

	gotEvidence, gotObservation, err := FromDNSEvent(event)
	if err != nil {
		t.Fatalf("FromDNSEvent() error = %v", err)
	}

	if gotEvidence.ID != "dns-address:api.example.com:192.0.2.10" {
		t.Errorf("Evidence.ID = %q", gotEvidence.ID)
	}
	if gotEvidence.EntityID != "api.example.com" {
		t.Errorf("Evidence.EntityID = %q", gotEvidence.EntityID)
	}
	if gotEvidence.Value != "192.0.2.10" {
		t.Errorf("Evidence.Value = %q", gotEvidence.Value)
	}
	if gotObservation.ID != "observation:dns-001" {
		t.Errorf("Observation.ID = %q", gotObservation.ID)
	}
	if gotObservation.EvidenceID != gotEvidence.ID {
		t.Errorf("Observation.EvidenceID = %q", gotObservation.EvidenceID)
	}
	if gotObservation.Source != event.Source {
		t.Errorf("Observation.Source = %q", gotObservation.Source)
	}
	if !gotObservation.ObservedAt.Equal(event.Timestamp) {
		t.Error("Observation timestamp does not match event timestamp")
	}
	if len(gotObservation.EventIDs) != 1 ||
		gotObservation.EventIDs[0] != event.ID {
		t.Errorf("Observation.EventIDs = %v", gotObservation.EventIDs)
	}
}

func TestFromDNSEventRejectsInvalidInput(t *testing.T) {
	valid := events.Event{
		ID:        "dns-001",
		Type:      events.EventDNSRecordFound,
		Timestamp: time.Now().UTC(),
		Target:    "example.com",
		Source:    "dns-collector",
		Data: map[string]string{
			"record_type": "IP_ADDRESS",
			"value":       "192.0.2.10",
		},
	}

	tests := []struct {
		name   string
		mutate func(*events.Event)
	}{
		{
			name: "non-DNS event",
			mutate: func(e *events.Event) {
				e.Type = events.EventPortDiscovered
			},
		},
		{
			name: "invalid IP",
			mutate: func(e *events.Event) {
				e.Data["value"] = "999.999.999.999"
			},
		},
		{
			name: "unsupported record type",
			mutate: func(e *events.Event) {
				e.Data["record_type"] = "CNAME"
			},
		},
		{
			name: "missing event ID",
			mutate: func(e *events.Event) {
				e.ID = ""
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := valid
			event.Data = map[string]string{
				"record_type": valid.Data["record_type"],
				"value":       valid.Data["value"],
			}
			tt.mutate(&event)

			if _, _, err := FromDNSEvent(event); err == nil {
				t.Fatal("FromDNSEvent() expected an error")
			}
		})
	}
}

func TestFromDNSEventKeepsEvidenceIdentityAcrossObservations(t *testing.T) {
	first := events.Event{
		ID:        "dns-001",
		Type:      events.EventDNSRecordFound,
		Timestamp: time.Now().UTC(),
		Target:    "example.com",
		Source:    "dns-collector",
		Data: map[string]string{
			"record_type": "IP_ADDRESS",
			"value":       "192.0.2.10",
		},
	}

	second := first
	second.ID = "dns-002"
	second.Timestamp = first.Timestamp.Add(time.Minute)

	firstEvidence, firstObservation, err := FromDNSEvent(first)
	if err != nil {
		t.Fatal(err)
	}

	secondEvidence, secondObservation, err := FromDNSEvent(second)
	if err != nil {
		t.Fatal(err)
	}

	if firstEvidence.ID != secondEvidence.ID {
		t.Fatal("same hostname and IP should produce the same evidence ID")
	}
	if firstObservation.ID == secondObservation.ID {
		t.Fatal("different event IDs should produce different observation IDs")
	}
}
