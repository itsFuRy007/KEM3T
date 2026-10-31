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

func validTLSEvent() events.Event {
	return events.Event{
		ID:        "tls-001",
		Type:      events.EventTLSCertificateFound,
		Timestamp: time.Date(2026, 10, 27, 1, 0, 0, 0, time.UTC),
		Target:    "API.Example.com",
		Source:    "tls-collector",
		Data: map[string]string{
			"port":                 "443",
			"subject":              "CN=api.example.com",
			"issuer":               "CN=Example CA",
			"serial_number":        "12345",
			"dns_names":            `["api.example.com"]`,
			"ip_addresses":         `["192.0.2.10"]`,
			"not_before":           "2026-01-01T00:00:00Z",
			"not_after":            "2027-01-01T00:00:00Z",
			"sha256_fingerprint":   "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			"signature_algorithm":  "ECDSA-SHA256",
			"public_key_algorithm": "ECDSA",
			"tls_version":          "TLS 1.3",
			"verified":             "true",
		},
	}
}

func TestFromTLSEvent(t *testing.T) {
	event := validTLSEvent()

	gotEvidence, gotObservation, err := FromTLSEvent(event)
	if err != nil {
		t.Fatalf("FromTLSEvent() error = %v", err)
	}

	if gotEvidence.Type != TypeTLSCertificate {
		t.Errorf("Evidence.Type = %q", gotEvidence.Type)
	}
	if gotEvidence.EntityID != "api.example.com" {
		t.Errorf("Evidence.EntityID = %q", gotEvidence.EntityID)
	}
	if gotEvidence.ID != "tls-certificate:api.example.com:443:"+event.Data["sha256_fingerprint"] {
		t.Errorf("Evidence.ID = %q", gotEvidence.ID)
	}
	if err := gotEvidence.Validate(); err != nil {
		t.Fatalf("Evidence.Validate() error = %v", err)
	}
	if gotObservation.ID != "observation:"+event.ID {
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
}

func TestFromTLSEventRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*events.Event)
	}{
		{
			name: "wrong event type",
			mutate: func(e *events.Event) {
				e.Type = events.EventPortDiscovered
			},
		},
		{
			name: "invalid port",
			mutate: func(e *events.Event) {
				e.Data["port"] = "70000"
			},
		},
		{
			name: "invalid fingerprint",
			mutate: func(e *events.Event) {
				e.Data["sha256_fingerprint"] = "not-a-fingerprint"
			},
		},
		{
			name: "invalid DNS names JSON",
			mutate: func(e *events.Event) {
				e.Data["dns_names"] = "not-json"
			},
		},
		{
			name: "invalid timestamp",
			mutate: func(e *events.Event) {
				e.Data["not_before"] = "not-a-time"
			},
		},
		{
			name: "invalid verified value",
			mutate: func(e *events.Event) {
				e.Data["verified"] = "maybe"
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := validTLSEvent()
			tt.mutate(&event)

			if _, _, err := FromTLSEvent(event); err == nil {
				t.Fatal("FromTLSEvent() expected an error")
			}
		})
	}
}

func TestFromTLSEventKeepsEvidenceIdentityAcrossObservations(t *testing.T) {
	first := validTLSEvent()
	second := validTLSEvent()
	second.ID = "tls-002"
	second.Timestamp = first.Timestamp.Add(time.Minute)

	firstEvidence, firstObservation, err := FromTLSEvent(first)
	if err != nil {
		t.Fatal(err)
	}
	secondEvidence, secondObservation, err := FromTLSEvent(second)
	if err != nil {
		t.Fatal(err)
	}

	if firstEvidence.ID != secondEvidence.ID {
		t.Fatal("same target, port, and certificate fingerprint should produce the same evidence ID")
	}
	if firstObservation.ID == secondObservation.ID {
		t.Fatal("different event IDs should produce different observation IDs")
	}
}

  
// TestFromDNSEventNormalizesTrailingDotAndCase keeps DNS evidence identity canonical.
func TestFromDNSEventNormalizesTrailingDotAndCase(t *testing.T) {
	event := events.Event{
		ID:        "dns-absolute-name",
		Type:      events.EventDNSRecordFound,
		Timestamp: time.Date(2026, 10, 31, 1, 0, 0, 0, time.UTC),
		Target:    "API.Example.com.",
		Source:    "dns-collector",
		Data: map[string]string{
			"record_type": "IP_ADDRESS",
			"value":       "192.0.2.10",
		},
	}
	got, _, err := FromDNSEvent(event)
	if err != nil {
		t.Fatalf("FromDNSEvent() error = %v", err)
	}
	if got.EntityID != "api.example.com" {
		t.Fatalf("EntityID = %q, want api.example.com", got.EntityID)
	}
	if got.ID != "dns-address:api.example.com:192.0.2.10" {
		t.Fatalf("Evidence ID = %q, want canonical identity", got.ID)
	}
}
