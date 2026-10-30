package events

import (
	"errors"
	"strings"
	"time"
)

// EventType identifies the kind of observation collected.
type EventType string

const (
	EventSubdomainDiscovered  EventType = "SUBDOMAIN_DISCOVERED"
	EventDNSRecordFound       EventType = "DNS_RECORD_FOUND"
	EventPortDiscovered       EventType = "PORT_DISCOVERED"
	EventTCPPortStateObserved EventType = "TCP_PORT_STATE_OBSERVED"
	EventServiceIdentified    EventType = "SERVICE_IDENTIFIED"
	EventTLSCertificateFound  EventType = "TLS_CERTIFICATE_FOUND"
	EventHTTPObserved         EventType = "HTTP_OBSERVED"
	EventAssetChanged         EventType = "ASSET_CHANGED"
)

// Event represents a normalized observation from a collector.
type Event struct {
	ID        string
	Type      EventType
	Timestamp time.Time
	Target    string
	Source    string
	Data      map[string]string
}

// Validate checks whether the event contains the required fields.
func (e Event) Validate() error {
	if strings.TrimSpace(e.ID) == "" {
		return errors.New("event ID is required")
	}

	if !e.Type.IsValid() {
		return errors.New("event type is invalid")
	}

	if e.Timestamp.IsZero() {
		return errors.New("event timestamp is required")
	}

	if strings.TrimSpace(e.Target) == "" {
		return errors.New("event target is required")
	}

	if strings.TrimSpace(e.Source) == "" {
		return errors.New("event source is required")
	}

	return nil
}

// IsValid reports whether the event type is supported.
func (t EventType) IsValid() bool {
	switch t {
	case EventSubdomainDiscovered,
		EventDNSRecordFound,
		EventPortDiscovered,
		EventTCPPortStateObserved,
		EventServiceIdentified,
		EventTLSCertificateFound,
		EventHTTPObserved,
		EventAssetChanged:
		return true
	default:
		return false
	}
}
