package evidence

import (
	"fmt"
	"net"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/events"
)

// FromDNSEvent converts a DNS IP-address event into evidence and an observation.
func FromDNSEvent(event events.Event) (Evidence, Observation, error) {
	if err := event.Validate(); err != nil {
		return Evidence{}, Observation{}, fmt.Errorf("validate event: %w", err)
	}

	if event.Type != events.EventDNSRecordFound {
		return Evidence{}, Observation{}, fmt.Errorf("event is not a DNS record event")
	}

	if !strings.EqualFold(
		strings.TrimSpace(event.Data["record_type"]),
		"IP_ADDRESS",
	) {
		return Evidence{}, Observation{}, fmt.Errorf("unsupported DNS record type")
	}

	target := strings.ToLower(strings.TrimSpace(event.Target))
	ip := net.ParseIP(strings.TrimSpace(event.Data["value"]))
	if ip == nil {
		return Evidence{}, Observation{}, fmt.Errorf("invalid DNS IP address")
	}

	address := ip.String()
	evidenceID := "dns-address:" + target + ":" + address

	e := Evidence{
		ID:       evidenceID,
		EntityID: target,
		Type:     TypeDNSAddress,
		Value:    address,
	}

	o := Observation{
		ID:         "observation:" + strings.TrimSpace(event.ID),
		EvidenceID: evidenceID,
		Source:     strings.TrimSpace(event.Source),
		ObservedAt: event.Timestamp,
		EventIDs:   []string{strings.TrimSpace(event.ID)},
	}

	if err := e.Validate(); err != nil {
		return Evidence{}, Observation{}, fmt.Errorf("validate evidence: %w", err)
	}

	if err := o.Validate(); err != nil {
		return Evidence{}, Observation{}, fmt.Errorf("validate observation: %w", err)
	}

	return e, o, nil
}
