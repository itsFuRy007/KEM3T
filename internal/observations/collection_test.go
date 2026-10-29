package observations

import (
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

func TestNormalizeEventsAggregatesServiceEvidenceConservatively(t *testing.T) {
	at := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	input := []events.Event{
		{ID: "tcp-1", Type: events.EventPortDiscovered, Timestamp: at, Target: "Example.COM.", Source: "tcp", Data: map[string]string{"protocol": "tcp", "port": "443", "state": "open"}},
		{ID: "http-1", Type: events.EventHTTPObserved, Timestamp: at.Add(time.Minute), Target: "example.com", Source: "http", Data: map[string]string{"scheme": "https", "port": "443", "status_code": "200", "server": "test-server"}},
		{ID: "bad-1", Type: events.EventHTTPObserved, Timestamp: at, Target: "example.com", Source: "http", Data: map[string]string{"scheme": "ftp", "port": "443", "status_code": "200"}},
	}
	got := NormalizeEvents(input)
	if len(got.Observations) != 2 {
		t.Fatalf("expected 2 normalized observations, got %d", len(got.Observations))
	}
	if len(got.Rejected) != 1 || got.Rejected[0].EventID != "bad-1" {
		t.Fatalf("expected invalid event to be recorded as a rejection: %#v", got.Rejected)
	}
	if len(got.Services) != 1 {
		t.Fatalf("expected one merged service, got %d", len(got.Services))
	}
	service := got.Services[0]
	if service.ID != "service:example.com:443:https" || service.Application != "https" {
		t.Fatalf("unexpected service identity: %#v", service)
	}
	if service.State != "open" || service.Indicators["http_status_code"] != "200" || service.Indicators["server"] != "test-server" {
		t.Fatalf("expected TCP and HTTP observations to enrich the same service: %#v", service)
	}
	if len(service.Sources) != 2 || service.Sources[0] != "http" || service.Sources[1] != "tcp" {
		t.Fatalf("service source provenance is not deterministic: %#v", service.Sources)
	}
	if !service.ObservedAt.Equal(at.Add(time.Minute)) {
		t.Fatalf("service timestamp should be the newest observation, got %s", service.ObservedAt)
	}
}

func TestBuildServicesDoesNotInferApplicationFromPort(t *testing.T) {
	observation := Observation{
		EventID: "tcp-1", Kind: KindTCPPort, Target: "example.com",
		Protocol: "tcp", Port: 443, Value: "open", Source: "tcp",
		ObservedAt: time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC),
	}
	got := BuildServices([]Observation{observation})
	if len(got) != 1 {
		t.Fatalf("expected one service, got %d", len(got))
	}
	if got[0].Application != "" || got[0].ID != "service:example.com:443:unknown" {
		t.Fatalf("TCP port alone must not imply HTTPS: %#v", got[0])
	}
}
