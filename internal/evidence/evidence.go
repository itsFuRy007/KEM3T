package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Type identifies the kind of fact supported by an observation.
type Type string

const (
	TypeDNSAddress     Type = "DNS_ADDRESS"
	TypeTLSCertificate Type = "TLS_CERTIFICATE"
	TypeTCPPort        Type = "TCP_PORT"
)

// TLSCertificateDetails contains the certificate metadata stored in evidence.
type TLSCertificateDetails struct {
	Target             string    `json:"target"`
	Port               int       `json:"port"`
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	DNSNames           []string  `json:"dns_names"`
	IPAddresses        []string  `json:"ip_addresses"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	SHA256Fingerprint  string    `json:"sha256_fingerprint"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	TLSVersion         string    `json:"tls_version"`
	Verified           bool      `json:"verified"`
}

// TCPPortDetails contains metadata for a discovered TCP port.
type TCPPortDetails struct {
	Target   string `json:"target"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	State    string `json:"state"`
}

// Evidence represents a normalized fact about an entity.
// It does not store individual observation timestamps or event references.
type Evidence struct {
	ID       string `json:"id"`
	EntityID string `json:"entity_id"`
	Type     Type   `json:"type"`
	Value    string `json:"value"`
}

// Validate checks whether the evidence has the required fields and valid content.
func (e Evidence) Validate() error {
	if strings.TrimSpace(e.ID) == "" {
		return errors.New("evidence ID is required")
	}

	if strings.TrimSpace(e.EntityID) == "" {
		return errors.New("evidence entity ID is required")
	}

	if strings.TrimSpace(e.Value) == "" {
		return errors.New("evidence value is required")
	}

	switch e.Type {
	case TypeDNSAddress:
		if !IsValidDomain(e.EntityID) {
			return errors.New("DNS evidence entity ID must be a valid domain")
		}
		if net.ParseIP(strings.TrimSpace(e.Value)) == nil {
			return errors.New("DNS address evidence must contain a valid IP address")
		}
		return nil

	case TypeTLSCertificate:
		return validateTLSCertificateEvidence(e)

	case TypeTCPPort:
		return validateTCPPortEvidence(e)

	default:
		return errors.New("evidence type is invalid")
	}
}

func validateTLSCertificateEvidence(e Evidence) error {
	target := strings.TrimSpace(e.EntityID)
	if !IsValidDomain(target) && net.ParseIP(target) == nil {
		return errors.New("TLS evidence entity ID must be a valid domain or IP address")
	}

	var details TLSCertificateDetails
	if err := json.Unmarshal([]byte(e.Value), &details); err != nil {
		return fmt.Errorf("TLS certificate evidence value must be valid JSON: %w", err)
	}

	if strings.TrimSpace(details.Target) == "" {
		return errors.New("TLS certificate target is required")
	}

	normalizedTarget := strings.TrimSuffix(
		strings.ToLower(strings.TrimSpace(details.Target)), ".",
	)
	normalizedEntity := strings.TrimSuffix(strings.ToLower(target), ".")
	if normalizedTarget != normalizedEntity {
		return errors.New("TLS certificate target must match evidence entity ID")
	}

	if details.Port < 1 || details.Port > 65535 {
		return errors.New("TLS certificate port must be between 1 and 65535")
	}

	fingerprint := strings.TrimSpace(details.SHA256Fingerprint)
	if len(fingerprint) != sha256.Size*2 {
		return errors.New("TLS certificate SHA-256 fingerprint must contain 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		return errors.New("TLS certificate SHA-256 fingerprint must be hexadecimal")
	}

	if details.NotBefore.IsZero() || details.NotAfter.IsZero() {
		return errors.New("TLS certificate validity timestamps are required")
	}
	if details.NotAfter.Before(details.NotBefore) {
		return errors.New("TLS certificate expiry must not precede its start date")
	}

	if strings.TrimSpace(details.TLSVersion) == "" {
		return errors.New("TLS certificate protocol version is required")
	}

	return nil
}

func validateTCPPortEvidence(e Evidence) error {
	target := strings.TrimSpace(e.EntityID)
	if !IsValidDomain(target) && net.ParseIP(target) == nil {
		return errors.New("TCP port evidence entity ID must be a valid domain or IP address")
	}

	var details TCPPortDetails
	if err := json.Unmarshal([]byte(e.Value), &details); err != nil {
		return fmt.Errorf("TCP port evidence value must be valid JSON: %w", err)
	}

	normalizedTarget := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(details.Target)), ".")
	normalizedEntity := strings.TrimSuffix(strings.ToLower(target), ".")
	if normalizedTarget == "" || normalizedTarget != normalizedEntity {
		return errors.New("TCP port target must match evidence entity ID")
	}
	if strings.ToLower(strings.TrimSpace(details.Protocol)) != "tcp" {
		return errors.New("TCP port protocol must be tcp")
	}
	if details.Port < 1 || details.Port > 65535 {
		return errors.New("TCP port must be between 1 and 65535")
	}
	if strings.ToLower(strings.TrimSpace(details.State)) != "open" {
		return errors.New("TCP port state must be open")
	}
	return nil
}
