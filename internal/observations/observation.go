package observations

import (
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/evidence"
)

// Kind identifies the normalized observation category independently of the
// collector-specific event payload.
type Kind string

const (
	KindDNSAddress     Kind = "dns_address"
	KindTCPPort        Kind = "tcp_port"
	KindTLSCertificate Kind = "tls_certificate"
	KindHTTPService    Kind = "http_service"
)

// Observation is the shared representation used to compare results from
// different collectors without discarding their source or original event ID.
type Observation struct {
	EventID    string            `json:"event_id"`
	Kind       Kind              `json:"kind"`
	Target     string            `json:"target"`
	Protocol   string            `json:"protocol,omitempty"`
	Port       int               `json:"port,omitempty"`
	Value      string            `json:"value"`
	Source     string            `json:"source"`
	ObservedAt time.Time         `json:"observed_at"`
	Attributes map[string]string `json:"attributes,omitempty"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
}

// Normalize converts supported collector events to a stable shared shape.
// It intentionally does not infer application services from port numbers.
func Normalize(event events.Event) (Observation, error) {
	if err := event.Validate(); err != nil {
		return Observation{}, fmt.Errorf("validate event: %w", err)
	}
	target := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(event.Target)), ".")
	out := Observation{
		EventID: strings.TrimSpace(event.ID), Target: target,
		Source: strings.TrimSpace(event.Source), ObservedAt: event.Timestamp.UTC(),
		Attributes: make(map[string]string),
	}
	for key, value := range event.Data {
		out.Attributes[key] = strings.TrimSpace(value)
	}

	switch event.Type {
	case events.EventDNSRecordFound:
		if !strings.EqualFold(strings.TrimSpace(event.Data["record_type"]), "IP_ADDRESS") {
			return Observation{}, fmt.Errorf("unsupported DNS record type")
		}
		ip := net.ParseIP(strings.TrimSpace(event.Data["value"]))
		if ip == nil {
			return Observation{}, fmt.Errorf("DNS value must be an IP address")
		}
		out.Kind, out.Protocol, out.Value = KindDNSAddress, "dns", ip.String()
	case events.EventPortDiscovered:
		if !strings.EqualFold(strings.TrimSpace(event.Data["protocol"]), "tcp") ||
			!strings.EqualFold(strings.TrimSpace(event.Data["state"]), "open") {
			return Observation{}, fmt.Errorf("TCP observation must describe an open TCP port")
		}
		port, err := parsePort(event.Data["port"])
		if err != nil {
			return Observation{}, err
		}
		out.Kind, out.Protocol, out.Port, out.Value = KindTCPPort, "tcp", port, "open"
	case events.EventTLSCertificateFound:
		port, err := parsePort(event.Data["port"])
		if err != nil {
			return Observation{}, err
		}
		fingerprint := strings.ToLower(strings.TrimSpace(event.Data["sha256_fingerprint"]))
		if len(fingerprint) != 64 {
			return Observation{}, fmt.Errorf("TLS SHA-256 fingerprint must contain 64 hexadecimal characters")
		}
		if _, err := hex.DecodeString(fingerprint); err != nil {
			return Observation{}, fmt.Errorf("TLS fingerprint must be hexadecimal")
		}
		out.Kind, out.Protocol, out.Port, out.Value = KindTLSCertificate, "tls", port, fingerprint
	case events.EventHTTPObserved:
		port, err := parsePort(event.Data["port"])
		if err != nil {
			return Observation{}, err
		}
		scheme := strings.ToLower(strings.TrimSpace(event.Data["scheme"]))
		if scheme != "http" && scheme != "https" {
			return Observation{}, fmt.Errorf("HTTP scheme must be http or https")
		}
		status, err := strconv.Atoi(strings.TrimSpace(event.Data["status_code"]))
		if err != nil || status < 100 || status > 599 {
			return Observation{}, fmt.Errorf("HTTP status code must be between 100 and 599")
		}
		out.Kind, out.Protocol, out.Port = KindHTTPService, scheme, port
		out.Value = strconv.Itoa(status)
	default:
		return Observation{}, fmt.Errorf("event type %q cannot be normalized as infrastructure observation", event.Type)
	}
	if out.Target == "" {
		return Observation{}, fmt.Errorf("normalized target is required")
	}
	return out, nil
}

func parsePort(raw string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("port must be between 1 and 65535")
	}
	return port, nil
}


// AttachEvidence links normalized observations to the existing evidence
// provenance records by their original collector event IDs, then rebuilds
// service aggregates so every service carries its evidence references.
func AttachEvidence(collection *Collection, links []evidence.Observation) {
	if collection == nil {
		return
	}
	evidenceByEvent := make(map[string][]string)
	for _, link := range links {
		for _, eventID := range link.EventIDs {
			evidenceByEvent[strings.TrimSpace(eventID)] = appendUniqueID(evidenceByEvent[strings.TrimSpace(eventID)], link.EvidenceID)
		}
	}
	for i := range collection.Observations {
		observation := &collection.Observations[i]
		for _, id := range evidenceByEvent[observation.EventID] {
			observation.EvidenceIDs = appendUniqueID(observation.EvidenceIDs, id)
		}
		sort.Strings(observation.EvidenceIDs)
	}
	collection.Services = BuildServices(collection.Observations)
}

func appendUniqueID(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
