package intelligence

import (
	"context"
	"fmt"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/events"
)

// Engine converts observed events into evidence-backed findings.
type Engine struct{}

// Analyze evaluates an event and returns a finding when relevant.
func (e *Engine) Analyze(event events.Event) (*Finding, error) {
	if err := event.Validate(); err != nil {
		return nil, fmt.Errorf("invalid event: %w", err)
	}

	switch event.Type {
	case events.EventSubdomainDiscovered:
		return analyzeSubdomain(event), nil
	default:
		return nil, nil
	}
}

func analyzeSubdomain(event events.Event) *Finding {
	hostname := strings.ToLower(strings.TrimSpace(event.Target))

	finding := &Finding{
		Title:     "Subdomain discovered",
		Priority:  PriorityInfo,
		Fact:      fmt.Sprintf("The hostname %s was discovered.", event.Target),
		Evidence:  []events.Event{event},
		NextSteps: []string{"Verify the asset and inspect its DNS records."},
	}

	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		switch label {
		case "dev", "development", "staging", "stage", "test", "qa":
			finding.Title = "Development-related hostname observed"
			finding.Priority = PriorityInterest
			finding.Observation = fmt.Sprintf(
				"The hostname contains the label %q.", label,
			)
			finding.PossibleSignificance =
				"It may indicate development or staging infrastructure; " +
					"the hostname alone does not confirm its purpose."
			finding.NextSteps = []string{
				"Verify the asset and resolve its DNS records.",
				"Identify exposed services before drawing further conclusions.",
			}
			return finding
		}
	}

	finding.Observation = "No development-related label was detected."
	finding.PossibleSignificance =
		"The hostname alone does not establish whether the asset is sensitive."
	return finding
}

// Run processes events until the input channel closes or the context ends.
func (e *Engine) Run(
	ctx context.Context,
	input <-chan events.Event,
	output chan<- Finding,
) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()

		case event, ok := <-input:
			if !ok {
				return nil
			}

			finding, err := e.Analyze(event)
			if err != nil {
				continue
			}

			if finding == nil {
				continue
			}

			select {
			case output <- *finding:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}
