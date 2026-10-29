package observations

import (
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

func event(kind events.EventType, data map[string]string) events.Event {
	return events.Event{
		ID: "event-1", Type: kind, Timestamp: time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC),
		Target: "Example.COM.", Source: "test-collector", Data: data,
	}
}

func TestNormalizeDNSObservation(t *testing.T) {
	got, err := Normalize(event(events.EventDNSRecordFound, map[string]string{
		"record_type": "IP_ADDRESS", "value": "2001:db8::1",
	}))
	if err != nil { t.Fatal(err) }
	if got.Kind != KindDNSAddress || got.Target != "example.com" || got.Value != "2001:db8::1" || got.Protocol != "dns" {
		t.Fatalf("unexpected normalized DNS observation: %#v", got)
	}
}

func TestNormalizeTCPDoesNotGuessApplicationFromPort(t *testing.T) {
	got, err := Normalize(event(events.EventPortDiscovered, map[string]string{
		"protocol": "tcp", "port": "443", "state": "open",
	}))
	if err != nil { t.Fatal(err) }
	service, err := IdentifyService(got, "evidence:tcp-443")
	if err != nil { t.Fatal(err) }
	if service.Application != "" || service.ID != "service:example.com:443:unknown" {
		t.Fatalf("TCP-only observation guessed an application: %#v", service)
	}
	if len(service.EvidenceIDs) != 1 || service.EvidenceIDs[0] != "evidence:tcp-443" {
		t.Fatalf("evidence provenance missing: %#v", service.EvidenceIDs)
	}
}

func TestNormalizeHTTPIdentifiesObservedScheme(t *testing.T) {
	got, err := Normalize(event(events.EventHTTPObserved, map[string]string{
		"scheme": "https", "port": "443", "status_code": "200",
		"server": "example-server",
	}))
	if err != nil { t.Fatal(err) }
	service, err := IdentifyService(got, "evidence:http-1")
	if err != nil { t.Fatal(err) }
	if service.Application != "https" || service.Indicators["http_status_code"] != "200" {
		t.Fatalf("HTTP evidence not reflected in service: %#v", service)
	}
	if service.Indicators["server"] != "example-server" {
		t.Fatalf("collector attributes not preserved: %#v", service.Indicators)
	}
}

func TestNormalizeRejectsInvalidPortsAndTLSFingerprint(t *testing.T) {
	tests := []events.Event{
		event(events.EventPortDiscovered, map[string]string{"protocol":"tcp", "port":"70000", "state":"open"}),
		event(events.EventTLSCertificateFound, map[string]string{"port":"443", "sha256_fingerprint":"not-a-fingerprint"}),
	}
	for _, item := range tests {
		if _, err := Normalize(item); err == nil {
			t.Fatalf("Normalize(%s) unexpectedly succeeded", item.Type)
		}
	}
}

func TestIdentifyServiceRejectsDNSObservation(t *testing.T) {
	observation, err := Normalize(event(events.EventDNSRecordFound, map[string]string{
		"record_type":"IP_ADDRESS", "value":"192.0.2.1",
	}))
	if err != nil { t.Fatal(err) }
	if _, err := IdentifyService(observation); err == nil {
		t.Fatal("expected DNS observation to be rejected as a service")
	}
}
