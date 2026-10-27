package intelligence

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/events"
)

// Aggregator groups DNS observations by normalized hostname.
type Aggregator struct {
	evidenceByTarget map[string][]events.Event
	eventIDs         map[string]struct{}
}

// NewAggregator creates an empty DNS event aggregator.
func NewAggregator() *Aggregator {
	return &Aggregator{
		evidenceByTarget: make(map[string][]events.Event),
		eventIDs:         make(map[string]struct{}),
	}
}

// Add validates and stores a DNS observation.
func (a *Aggregator) Add(event events.Event) error {
	if err := event.Validate(); err != nil {
		return fmt.Errorf("invalid event: %w", err)
	}

	if event.Type != events.EventDNSRecordFound {
		return fmt.Errorf("unsupported event type %q", event.Type)
	}

	recordType := strings.ToUpper(strings.TrimSpace(event.Data["record_type"]))
	if recordType != "IP_ADDRESS" {
		return fmt.Errorf("unsupported DNS record type %q", recordType)
	}

	value := strings.TrimSpace(event.Data["value"])
	ip := net.ParseIP(value)
	if ip == nil {
		return fmt.Errorf("invalid IP address %q", value)
	}

	id := strings.TrimSpace(event.ID)
	if _, exists := a.eventIDs[id]; exists {
		return fmt.Errorf("duplicate event ID %q", id)
	}

	target := strings.ToLower(strings.TrimSpace(event.Target))
	if target == "" {
		return fmt.Errorf("DNS target is required")
	}

	// Store a normalized copy of the IP value.
	event.Data = cloneData(event.Data)
	event.Data["record_type"] = "IP_ADDRESS"
	event.Data["value"] = ip.String()

	a.eventIDs[id] = struct{}{}
	a.evidenceByTarget[target] = append(a.evidenceByTarget[target], event)

	return nil
}

// Findings returns one summary finding per hostname.
func (a *Aggregator) Findings() []Finding {
	targets := make([]string, 0, len(a.evidenceByTarget))
	for target := range a.evidenceByTarget {
		targets = append(targets, target)
	}
	sort.Strings(targets)

	findings := make([]Finding, 0, len(targets))

	for _, target := range targets {
		evidence := append([]events.Event(nil), a.evidenceByTarget[target]...)

		addressSet := make(map[string]struct{})
		for _, event := range evidence {
			addressSet[event.Data["value"]] = struct{}{}
		}

		addresses := make([]string, 0, len(addressSet))
		for address := range addressSet {
			addresses = append(addresses, address)
		}
		sort.Strings(addresses)

		findings = append(findings, Finding{
			Title:    "DNS addresses summarized",
			Priority: PriorityInfo,
			Fact: fmt.Sprintf(
				"Hostname %s resolved to %d unique IP address(es): %s.",
				target,
				len(addresses),
				strings.Join(addresses, ", "),
			),
			Observation: fmt.Sprintf(
				"Collected %d DNS observation(s) containing %d unique address(es).",
				len(evidence),
				len(addresses),
			),
			PossibleSignificance: "These observations describe resolver results at collection time; they do not establish that any address is vulnerable.",
			Evidence:             evidence,
			NextSteps: []string{
				"Compare future DNS observations to identify changes.",
				"Verify the asset and collect authorized service information.",
			},
		})
	}

	return findings
}

func cloneData(data map[string]string) map[string]string {
	if data == nil {
		return nil
	}

	clone := make(map[string]string, len(data))
	for key, value := range data {
		clone[key] = value
	}
	return clone
}
