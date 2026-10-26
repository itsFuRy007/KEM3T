package events

import (
	"testing"
	"time"
)

func TestValidEvent(t *testing.T) {
	event := Event{
		ID:        "event-001",
		Type:      EventSubdomainDiscovered,
		Timestamp: time.Now(),
		Target:    "dev.example.com",
		Source:    "test-collector",
		Data: map[string]string{
			"hostname": "dev.example.com",
		},
	}

	if err := event.Validate(); err != nil {
		t.Fatalf("expected valid event, got error: %v", err)
	}
}

func TestInvalidEventType(t *testing.T) {
	event := Event{
		ID:        "event-002",
		Type:      "UNKNOWN_EVENT",
		Timestamp: time.Now(),
		Target:    "example.com",
		Source:    "test-collector",
	}

	if err := event.Validate(); err == nil {
		t.Fatal("expected invalid event type to return an error")
	}
}

func TestMissingTarget(t *testing.T) {
	event := Event{
		ID:        "event-003",
		Type:      EventSubdomainDiscovered,
		Timestamp: time.Now(),
		Source:    "test-collector",
	}

	if err := event.Validate(); err == nil {
		t.Fatal("expected missing target to return an error")
	}
}
