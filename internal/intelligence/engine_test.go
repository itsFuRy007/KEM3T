package intelligence

import (
	"context"
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
