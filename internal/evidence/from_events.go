package evidence

import (
	"encoding/json"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

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

// FromTCPEvent converts an open TCP port event into evidence and an observation.
func FromTCPEvent(event events.Event) (Evidence, Observation, error) {
	if err := event.Validate(); err != nil {
		return Evidence{}, Observation{}, fmt.Errorf("validate event: %w", err)
	}
	if event.Type != events.EventPortDiscovered {
		return Evidence{}, Observation{}, fmt.Errorf("event is not a port discovery event")
	}
	target := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(event.Target)), ".")
	if !IsValidDomain(target) && net.ParseIP(target) == nil {
		return Evidence{}, Observation{}, fmt.Errorf("invalid TCP target")
	}
	if !strings.EqualFold(strings.TrimSpace(event.Data["protocol"]), "tcp") ||
		!strings.EqualFold(strings.TrimSpace(event.Data["state"]), "open") {
		return Evidence{}, Observation{}, fmt.Errorf("event must describe an open TCP port")
	}
	port, err := strconv.Atoi(strings.TrimSpace(event.Data["port"]))
	if err != nil || port < 1 || port > 65535 {
		return Evidence{}, Observation{}, fmt.Errorf("invalid TCP port")
	}
	details := TCPPortDetails{Target: target, Protocol: "tcp", Port: port, State: "open"}
	value, err := json.Marshal(details)
	if err != nil {
		return Evidence{}, Observation{}, fmt.Errorf("encode TCP evidence: %w", err)
	}
	evidenceID := fmt.Sprintf("tcp-port:%s:%d", target, port)
	e := Evidence{ID: evidenceID, EntityID: target, Type: TypeTCPPort, Value: string(value)}
	o := Observation{
		ID: "observation:" + strings.TrimSpace(event.ID), EvidenceID: evidenceID,
		Source: strings.TrimSpace(event.Source), ObservedAt: event.Timestamp,
		EventIDs: []string{strings.TrimSpace(event.ID)},
	}
	if err := e.Validate(); err != nil {
		return Evidence{}, Observation{}, fmt.Errorf("validate evidence: %w", err)
	}
	if err := o.Validate(); err != nil {
		return Evidence{}, Observation{}, fmt.Errorf("validate observation: %w", err)
	}
	return e, o, nil
}

// FromTLSEvent converts a TLS certificate event into evidence and an observation.
func FromTLSEvent(event events.Event) (Evidence, Observation, error) {
	if err := event.Validate(); err != nil {
		return Evidence{}, Observation{}, fmt.Errorf("validate event: %w", err)
	}
	if event.Type != events.EventTLSCertificateFound {
		return Evidence{}, Observation{}, fmt.Errorf("event is not a TLS certificate event")
	}

	target := strings.ToLower(strings.TrimSpace(event.Target))
	target = strings.TrimSuffix(target, ".")
	if target == "" || (net.ParseIP(target) == nil && !IsValidDomain(target)) {
		return Evidence{}, Observation{}, fmt.Errorf("invalid TLS target")
	}

	port, err := strconv.Atoi(strings.TrimSpace(event.Data["port"]))
	if err != nil || port < 1 || port > 65535 {
		return Evidence{}, Observation{}, fmt.Errorf("invalid TLS port")
	}

	var dnsNames []string
	if err := json.Unmarshal([]byte(event.Data["dns_names"]), &dnsNames); err != nil {
		return Evidence{}, Observation{}, fmt.Errorf("invalid TLS DNS names: %w", err)
	}

	var ipAddresses []string
	if err := json.Unmarshal([]byte(event.Data["ip_addresses"]), &ipAddresses); err != nil {
		return Evidence{}, Observation{}, fmt.Errorf("invalid TLS IP addresses: %w", err)
	}

	notBefore, err := time.Parse(time.RFC3339, strings.TrimSpace(event.Data["not_before"]))
	if err != nil {
		return Evidence{}, Observation{}, fmt.Errorf("invalid TLS not_before timestamp: %w", err)
	}

	notAfter, err := time.Parse(time.RFC3339, strings.TrimSpace(event.Data["not_after"]))
	if err != nil {
		return Evidence{}, Observation{}, fmt.Errorf("invalid TLS not_after timestamp: %w", err)
	}

	verified, err := strconv.ParseBool(strings.TrimSpace(event.Data["verified"]))
	if err != nil {
		return Evidence{}, Observation{}, fmt.Errorf("invalid TLS verified value: %w", err)
	}

	details := TLSCertificateDetails{
		Target:             target,
		Port:               port,
		Subject:            strings.TrimSpace(event.Data["subject"]),
		Issuer:             strings.TrimSpace(event.Data["issuer"]),
		SerialNumber:       strings.TrimSpace(event.Data["serial_number"]),
		DNSNames:           dnsNames,
		IPAddresses:        ipAddresses,
		NotBefore:          notBefore.UTC(),
		NotAfter:           notAfter.UTC(),
		SHA256Fingerprint:  strings.ToLower(strings.TrimSpace(event.Data["sha256_fingerprint"])),
		SignatureAlgorithm: strings.TrimSpace(event.Data["signature_algorithm"]),
		PublicKeyAlgorithm: strings.TrimSpace(event.Data["public_key_algorithm"]),
		TLSVersion:         strings.TrimSpace(event.Data["tls_version"]),
		Verified:           verified,
	}

	value, err := json.Marshal(details)
	if err != nil {
		return Evidence{}, Observation{}, fmt.Errorf("encode TLS certificate evidence: %w", err)
	}

	evidenceID := fmt.Sprintf(
		"tls-certificate:%s:%d:%s",
		target,
		port,
		details.SHA256Fingerprint,
	)

	e := Evidence{
		ID:       evidenceID,
		EntityID: target,
		Type:     TypeTLSCertificate,
		Value:    string(value),
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

 
// FromHTTPEvent converts a bounded HTTP response event into evidence and an observation.
func FromHTTPEvent(event events.Event) (Evidence, Observation, error) {
	if err := event.Validate(); err != nil { return Evidence{}, Observation{}, fmt.Errorf("validate event: %w", err) }
	if event.Type != events.EventHTTPObserved { return Evidence{}, Observation{}, fmt.Errorf("event is not an HTTP observation") }
	target := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(event.Target)), ".")
	if !IsValidDomain(target) && net.ParseIP(target) == nil { return Evidence{}, Observation{}, fmt.Errorf("invalid HTTP target") }
	port, err := strconv.Atoi(strings.TrimSpace(event.Data["port"]))
	if err != nil || port < 1 || port > 65535 { return Evidence{}, Observation{}, fmt.Errorf("invalid HTTP port") }
	status, err := strconv.Atoi(strings.TrimSpace(event.Data["status_code"]))
	if err != nil || status < 100 || status > 599 { return Evidence{}, Observation{}, fmt.Errorf("invalid HTTP status code") }
	redirects, err := strconv.Atoi(strings.TrimSpace(event.Data["redirect_count"]))
	if err != nil || redirects < 0 { return Evidence{}, Observation{}, fmt.Errorf("invalid HTTP redirect count") }
	truncated, err := strconv.ParseBool(strings.TrimSpace(event.Data["body_truncated"]))
	if err != nil { return Evidence{}, Observation{}, fmt.Errorf("invalid HTTP body_truncated value: %w", err) }
	verified, err := strconv.ParseBool(strings.TrimSpace(event.Data["tls_verified"]))
	if err != nil { return Evidence{}, Observation{}, fmt.Errorf("invalid HTTP tls_verified value: %w", err) }
	details := HTTPServiceDetails{
		Target: target, Scheme: strings.ToLower(strings.TrimSpace(event.Data["scheme"])), Port: port,
		URL: strings.TrimSpace(event.Data["url"]), FinalURL: strings.TrimSpace(event.Data["final_url"]),
		StatusCode: status, ContentType: strings.TrimSpace(event.Data["content_type"]),
		Server: strings.TrimSpace(event.Data["server"]), PoweredBy: strings.TrimSpace(event.Data["powered_by"]),
		Title: strings.TrimSpace(event.Data["title"]), RedirectCount: redirects, BodyTruncated: truncated,
		TLSVersion: strings.TrimSpace(event.Data["tls_version"]), TLSVerified: verified,
	}
	value, err := json.Marshal(details)
	if err != nil { return Evidence{}, Observation{}, fmt.Errorf("encode HTTP evidence: %w", err) }
	sum := sha256.Sum256(value)
	evidenceID := "http-service:" + hex.EncodeToString(sum[:])
	item := Evidence{ID: evidenceID, EntityID: target, Type: TypeHTTPService, Value: string(value)}
	observation := Observation{ID: "observation:" + strings.TrimSpace(event.ID), EvidenceID: evidenceID,
		Source: strings.TrimSpace(event.Source), ObservedAt: event.Timestamp, EventIDs: []string{strings.TrimSpace(event.ID)}}
	if err := item.Validate(); err != nil { return Evidence{}, Observation{}, fmt.Errorf("validate evidence: %w", err) }
	if err := observation.Validate(); err != nil { return Evidence{}, Observation{}, fmt.Errorf("validate observation: %w", err) }
	return item, observation, nil
}
