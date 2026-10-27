package intelligence

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

func TestRunProcessesSubdomainEvent(t *testing.T) {
	engine := &Engine{}

	input := make(chan events.Event, 1)
	output := make(chan Finding, 1)

	input <- events.Event{
		ID:        "test-001",
		Type:      events.EventSubdomainDiscovered,
		Timestamp: time.Now().UTC(),
		Target:    "dev.example.com",
		Source:    "test",
	}
	close(input)

	err := engine.Run(context.Background(), input, output)
	if err != nil {
		t.Fatalf("Run returned an unexpected error: %v", err)
	}

	select {
	case finding := <-output:
		if finding.Priority != PriorityInterest {
			t.Errorf(
				"expected priority %q, got %q",
				PriorityInterest,
				finding.Priority,
			)
		}

		if len(finding.Evidence) != 1 {
			t.Errorf(
				"expected 1 evidence event, got %d",
				len(finding.Evidence),
			)
		}

	default:
		t.Fatal("expected a finding, but output was empty")
	}
}

func TestRunReturnsWhenInputCloses(t *testing.T) {
	engine := &Engine{}

	input := make(chan events.Event)
	output := make(chan Finding)

	close(input)

	err := engine.Run(context.Background(), input, output)
	if err != nil {
		t.Fatalf("expected nil error after input closes, got %v", err)
	}
}

func TestRunStopsWhenContextIsCanceled(t *testing.T) {
	engine := &Engine{}

	ctx, cancel := context.WithCancel(context.Background())
	input := make(chan events.Event)
	output := make(chan Finding)

	cancel()

	err := engine.Run(ctx, input, output)
	if err != context.Canceled {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
}

func TestRunReturnsErrorForInvalidEvent(t *testing.T) {
	engine := &Engine{}

	input := make(chan events.Event, 1)
	output := make(chan Finding, 1)

	input <- events.Event{
		ID:        "invalid-event-001",
		Type:      events.EventDNSRecordFound,
		Timestamp: time.Now().UTC(),
		Target:    "example.com",
		Source:    "test",
		Data: map[string]string{
			"record_type": "IP_ADDRESS",
			"value":       "not-an-ip",
		},
	}
	close(input)

	err := engine.Run(context.Background(), input, output)
	if err == nil {
		t.Fatal("expected an error for invalid DNS event")
	}

	if !strings.Contains(err.Error(), "invalid-event-001") {
		t.Fatalf("expected error to include event ID, got: %v", err)
	}
}
func TestAnalyzeSubdomainClassification(t *testing.T) {
	engine := &Engine{}

	tests := []struct {
		name     string
		target   string
		expected Priority
	}{
		{
			name:     "development label",
			target:   "dev.example.com",
			expected: PriorityInterest,
		},
		{
			name:     "word containing dev",
			target:   "device.example.com",
			expected: PriorityInfo,
		},
		{
			name:     "ordinary hostname",
			target:   "example.com",
			expected: PriorityInfo,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := events.Event{
				ID:        "classification-test",
				Type:      events.EventSubdomainDiscovered,
				Timestamp: time.Now().UTC(),
				Target:    tt.target,
				Source:    "test",
			}

			finding, err := engine.Analyze(event)
			if err != nil {
				t.Fatalf("Analyze returned an unexpected error: %v", err)
			}

			if finding == nil {
				t.Fatal("expected a finding, got nil")
			}

			if finding.Priority != tt.expected {
				t.Errorf(
					"expected priority %q, got %q",
					tt.expected,
					finding.Priority,
				)
			}
		})
	}
}
