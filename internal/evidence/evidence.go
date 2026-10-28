package evidence

import (
	"errors"
	"net"
	"strings"
)

// Type identifies the kind of fact supported by an observation.
type Type string

const (
	TypeDNSAddress Type = "DNS_ADDRESS"
)

// Evidence represents a normalized fact about an entity.
// It does not store individual observation timestamps or event references.
type Evidence struct {
	ID       string `json:"id"`
	EntityID string `json:"entity_id"`
	Type     Type   `json:"type"`
	Value    string `json:"value"`
}

// Validate checks whether the evidence has the required fields.
func (e Evidence) Validate() error {
	if strings.TrimSpace(e.ID) == "" {
		return errors.New("evidence ID is required")
	}

	if strings.TrimSpace(e.EntityID) == "" {
		return errors.New("evidence entity ID is required")
	}
	if !IsValidDomain(e.EntityID) {
		return errors.New("evidence entity ID must be a valid domain")
	}

	if e.Type != TypeDNSAddress {
		return errors.New("evidence type is invalid")
	}

	if strings.TrimSpace(e.Value) == "" {
		return errors.New("evidence value is required")
	}

	if net.ParseIP(strings.TrimSpace(e.Value)) == nil {
		return errors.New("DNS address evidence must contain a valid IP address")
	}

	return nil
}
