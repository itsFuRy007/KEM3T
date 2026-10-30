package integration

import (
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/observations"
)

// FuzzCoreInputValidation exercises the boundaries where untrusted collector
// payloads enter normalization, evidence validation, and report rendering.
// The goal is to guarantee malformed input is rejected or safely represented,
// never to make arbitrary input look like a valid observation.
func FuzzCoreInputValidation(f *testing.F) {
	f.Add("event-1", "DNS_RECORD_FOUND", "example.com", "fuzz", "IP_ADDRESS", "203.0.113.10", "DNS_ADDRESS", "443", "https")
	f.Add("event-2", "HTTP_OBSERVED", "api.example.com", "fuzz", "", "200", "HTTP_SERVICE", "65536", "http")
	f.Add("", "UNKNOWN", "not a hostname", "", "A", "not-an-ip", "UNKNOWN", "0", "ftp")
	f.Add("event-4", "TLS_CERTIFICATE_FOUND", "example.com", "fuzz", "", "not-json-or-a-fingerprint", "TLS_CERTIFICATE", "-1", "https")

	f.Fuzz(func(t *testing.T, id, eventType, target, source, recordType, value, evidenceType, port, scheme string) {
		event := events.Event{
			ID: id, Type: events.EventType(eventType), Timestamp: time.Unix(1, 0).UTC(),
			Target: target, Source: source,
			Data: map[string]string{
				"record_type": recordType, "value": value, "port": port,
				"scheme": scheme, "protocol": "tcp", "state": "open",
				"sha256_fingerprint": value, "status_code": value,
			},
		}
		_ = event.Validate()
		_, _ = observations.Normalize(event)

		item := evidence.Evidence{ID: id, EntityID: target, Type: evidence.Type(evidenceType), Value: value}
		_ = item.Validate()

		observation := evidence.Observation{
			ID: id, EvidenceID: id, Source: source, ObservedAt: time.Unix(1, 0).UTC(),
			EventIDs: []string{id},
		}
		_ = observation.Validate()

		report := intelligence.IntelligenceReport{
			Target: target,
			Narrative: intelligence.ResearchNarrative{Summary: value},
		}
		_, _ = intelligence.RenderMarkdownReport(report)
	})
}
