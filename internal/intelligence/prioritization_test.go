package intelligence

import (
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

func prioritizationTestFinding(title string, priority Priority) Finding {
	return Finding{
		Title:    title,
		Priority: priority,
		Fact:     "Test observation for " + title,
		Evidence: []events.Event{
			{
				ID:        "event-" + title,
				Type:      events.EventSubdomainDiscovered,
				Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				Target:    "example.com",
				Source:    "test",
			},
		},
	}
}

func TestPrioritizationEngineOrdersFindings(t *testing.T) {
	engine := &PrioritizationEngine{}

	input := []Finding{
		prioritizationTestFinding("Informational item", PriorityInfo),
		prioritizationTestFinding("High item", PriorityHigh),
		prioritizationTestFinding("Interesting item", PriorityInterest),
		prioritizationTestFinding("Low item", PriorityLow),
	}

	results, err := engine.Prioritize(input)
	if err != nil {
		t.Fatalf("Prioritize returned error: %v", err)
	}

	expected := []Priority{
		PriorityHigh,
		PriorityInterest,
		PriorityInfo,
		PriorityLow,
	}

	if len(results) != len(expected) {
		t.Fatalf("expected %d results, got %d", len(expected), len(results))
	}

	for i, priority := range expected {
		if results[i].Priority != priority {
			t.Errorf(
				"result %d: expected priority %q, got %q",
				i,
				priority,
				results[i].Priority,
			)
		}
		if results[i].Reason == "" {
			t.Errorf("result %d has no priority explanation", i)
		}
	}
}

func TestPrioritizationEnginePreservesSourcePriority(t *testing.T) {
	engine := &PrioritizationEngine{}
	input := []Finding{
		prioritizationTestFinding("Development hostname", PriorityInterest),
		prioritizationTestFinding("DNS result", PriorityInfo),
	}

	results, err := engine.Prioritize(input)
	if err != nil {
		t.Fatalf("Prioritize returned error: %v", err)
	}

	for _, result := range results {
		if result.Priority != result.Finding.Priority {
			t.Errorf(
				"priority changed from %q to %q",
				result.Finding.Priority,
				result.Priority,
			)
		}
	}
}

func TestPrioritizationEngineRejectsInvalidFinding(t *testing.T) {
	engine := &PrioritizationEngine{}

	_, err := engine.Prioritize([]Finding{
		{Title: "Missing required fields"},
	})
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestPrioritizationEngineIsDeterministic(t *testing.T) {
	engine := &PrioritizationEngine{}

	input := []Finding{
		prioritizationTestFinding("Zebra", PriorityInfo),
		prioritizationTestFinding("Alpha", PriorityInfo),
	}

	first, err := engine.Prioritize(input)
	if err != nil {
		t.Fatalf("first Prioritize returned error: %v", err)
	}

	second, err := engine.Prioritize(input)
	if err != nil {
		t.Fatalf("second Prioritize returned error: %v", err)
	}

	if first[0].Finding.Title != second[0].Finding.Title ||
		first[1].Finding.Title != second[1].Finding.Title {
		t.Fatal("prioritization order changed between identical runs")
	}
}
