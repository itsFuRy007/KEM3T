package intelligence

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// DNSHistoryComparison describes how DNS addresses differ between two observations.
type DNSHistoryComparison struct {
	Target        string
	Added         []string
	Removed       []string
	Unchanged     []string
	PreviousCount int
	CurrentCount  int
}

// CompareDNSHistory compares the previous and current DNS address sets.
// The comparison is deterministic and does not modify the input slices.
func CompareDNSHistory(
	target string,
	previous []string,
	current []string,
) (DNSHistoryComparison, error) {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return DNSHistoryComparison{}, fmt.Errorf("target is required")
	}

	previousSet, err := normalizeAddressSet(previous)
	if err != nil {
		return DNSHistoryComparison{}, fmt.Errorf("normalize previous addresses: %w", err)
	}

	currentSet, err := normalizeAddressSet(current)
	if err != nil {
		return DNSHistoryComparison{}, fmt.Errorf("normalize current addresses: %w", err)
	}

	result := DNSHistoryComparison{
		Target:        target,
		PreviousCount: len(previousSet),
		CurrentCount:  len(currentSet),
		Added:         make([]string, 0),
		Removed:       make([]string, 0),
		Unchanged:     make([]string, 0),
	}

	for address := range currentSet {
		if _, existed := previousSet[address]; existed {
			result.Unchanged = append(result.Unchanged, address)
		} else {
			result.Added = append(result.Added, address)
		}
	}

	for address := range previousSet {
		if _, exists := currentSet[address]; !exists {
			result.Removed = append(result.Removed, address)
		}
	}

	sort.Strings(result.Added)
	sort.Strings(result.Removed)
	sort.Strings(result.Unchanged)

	return result, nil
}

func normalizeAddressSet(addresses []string) (map[string]struct{}, error) {
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
