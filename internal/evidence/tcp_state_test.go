package evidence

import (
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

func TestFromTCPEventPersistsNonOpenStatesWithoutTreatingThemAsOpen(t *testing.T) {
	for _, state := range []string{"closed", "unknown"} {
		t.Run(state, func(t *testing.T) {
			event := events.Event{
				ID: "tcp-" + state, Type: events.EventTCPPortStateObserved,
				Timestamp: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC),
				Target: "127.0.0.1", Source: "tcp-collector",
				Data: map[string]string{"protocol": "tcp", "port": "32123", "state": state, "reason": "test reason"},
			}
			item, observation, err := FromTCPEvent(event)
			if err != nil { t.Fatalf("FromTCPEvent() error = %v", err) }
			if item.Type != TypeTCPPortObservation { t.Fatalf("evidence type = %q", item.Type) }
			if err := item.Validate(); err != nil { t.Fatalf("evidence validation: %v", err) }
			if observation.EvidenceID != item.ID { t.Fatal("observation does not reference state evidence") }
			if item.Type == TypeTCPPort { t.Fatal("non-open state was represented as open-port evidence") }
		})
	}
}

func TestFromTCPEventRejectsNonOpenStateWithoutReason(t *testing.T) {
	event := events.Event{
		ID: "tcp-unknown", Type: events.EventTCPPortStateObserved,
		Timestamp: time.Now().UTC(), Target: "127.0.0.1", Source: "tcp-collector",
		Data: map[string]string{"protocol": "tcp", "port": "32123", "state": "unknown"},
	}
	if _, _, err := FromTCPEvent(event); err == nil {
		t.Fatal("expected missing TCP state reason to be rejected")
	}
}
