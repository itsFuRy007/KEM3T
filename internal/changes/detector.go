package changes

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

type ChangeType string

const (
	AddressAdded   ChangeType = "ADDRESS_ADDED"
	AddressRemoved ChangeType = "ADDRESS_REMOVED"
)

type Change struct {
	Target  string
	Type    ChangeType
	Address string
}

type Snapshot struct {
	Target    string
	Addresses []string
}

type Detector struct{}

func NewDetector() *Detector {
	return &Detector{}
}

// Compare compares two snapshots of the same hostname.
func (d *Detector) Compare(previous, current Snapshot) ([]Change, error) {
	oldTarget := normalizeTarget(previous.Target)
	newTarget := normalizeTarget(current.Target)

	if oldTarget == "" || newTarget == "" {
		return nil, fmt.Errorf("both snapshot targets are required")
	}

	if oldTarget != newTarget {
		return nil, fmt.Errorf(
			"cannot compare different targets: %q and %q",
			oldTarget,
			newTarget,
		)
	}

	oldAddresses, err := normalizeAddresses(previous.Addresses)
	if err != nil {
		return nil, fmt.Errorf("invalid previous snapshot: %w", err)
	}

	newAddresses, err := normalizeAddresses(current.Addresses)
	if err != nil {
		return nil, fmt.Errorf("invalid current snapshot: %w", err)
	}

	var result []Change

	for address := range newAddresses {
		if _, exists := oldAddresses[address]; !exists {
			result = append(result, Change{
				Target:  oldTarget,
				Type:    AddressAdded,
				Address: address,
			})
		}
	}

	for address := range oldAddresses {
		if _, exists := newAddresses[address]; !exists {
			result = append(result, Change{
				Target:  oldTarget,
				Type:    AddressRemoved,
				Address: address,
			})
		}
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].Address != result[j].Address {
			return result[i].Address < result[j].Address
		}
		return result[i].Type < result[j].Type
	})

	return result, nil
}

func normalizeTarget(target string) string {
	return strings.ToLower(strings.TrimSpace(target))
}

func normalizeAddresses(addresses []string) (map[string]struct{}, error) {
	result := make(map[string]struct{}, len(addresses))

	for _, address := range addresses {
		address = strings.TrimSpace(address)
		ip := net.ParseIP(address)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP address %q", address)
		}

		result[ip.String()] = struct{}{}
	}

	return result, nil
}
