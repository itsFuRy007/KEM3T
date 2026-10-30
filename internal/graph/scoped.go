package graph

import (
	"fmt"
	"net"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

// BuildForTarget creates a graph containing only evidence in the requested
// target scope. For domain targets, DNS-derived IP addresses are included so
// IP-level evidence collected against those addresses can be represented.
// Evidence for unrelated domains and local interfaces is never pulled in just
// because it shares the same workspace registry.
func BuildForTarget(target string, records []evidence.Evidence, observations []evidence.Observation) (Graph, error) {
	target = normalizeGraphTarget(target)
	if target == "" {
		return Graph{}, fmt.Errorf("valid graph target is required")
	}

	inScopeIPs := make(map[string]struct{})
	if ip := net.ParseIP(target); ip != nil {
		inScopeIPs[ip.String()] = struct{}{}
	} else {
		for _, record := range records {
			if record.Type != evidence.TypeDNSAddress || !domainWithinGraphScope(record.EntityID, target) {
				continue
			}
			if ip := net.ParseIP(strings.TrimSpace(record.Value)); ip != nil {
				inScopeIPs[ip.String()] = struct{}{}
			}
		}
	}

	scopedRecords := make([]evidence.Evidence, 0, len(records))
	scopedIDs := make(map[string]struct{}, len(records))
	for _, record := range records {
		entity := normalizeGraphTarget(record.EntityID)
		inScope := entity == target
		if !inScope && net.ParseIP(target) == nil && net.ParseIP(entity) == nil {
			inScope = domainWithinGraphScope(entity, target)
		}
		if !inScope {
			if ip := net.ParseIP(entity); ip != nil {
				_, inScope = inScopeIPs[ip.String()]
			}
		}
		if !inScope {
			continue
		}
		scopedRecords = append(scopedRecords, record)
		scopedIDs[record.ID] = struct{}{}
	}

	scopedObservations := make([]evidence.Observation, 0, len(observations))
	for _, observation := range observations {
		if _, ok := scopedIDs[observation.EvidenceID]; ok {
			scopedObservations = append(scopedObservations, observation)
		}
	}
	return Build(scopedRecords, scopedObservations)
}

// BuildFromRegistryForTarget builds a target-scoped graph from a persistent
// workspace registry. BuildFromRegistry remains available for intentional
// whole-workspace graph views.
func BuildFromRegistryForTarget(registry *evidence.Registry, target string) (Graph, error) {
	if registry == nil {
		return Graph{}, fmt.Errorf("evidence registry is required")
	}
	return BuildForTarget(target, registry.AllEvidence(), registry.AllObservations())
}

func normalizeGraphTarget(value string) string {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	if !evidence.IsValidDomain(value) {
		return ""
	}
	return value
}

func domainWithinGraphScope(candidate, target string) bool {
	candidate = normalizeGraphTarget(candidate)
	if candidate == "" || target == "" || net.ParseIP(candidate) != nil || net.ParseIP(target) != nil {
		return false
	}
	return candidate == target || strings.HasSuffix(candidate, "."+target)
}
