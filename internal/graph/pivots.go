package graph

import (
	"fmt"
	"sort"
)

// PivotKind identifies a supported one-hop investigation pivot. Pivots only
// traverse relationships already present in the evidence-backed graph.
type PivotKind string

const (
	PivotDomainToIPs        PivotKind = "DOMAIN_TO_IPS"
	PivotDomainToServices   PivotKind = "DOMAIN_TO_SERVICES"
	PivotIPToDomains        PivotKind = "IP_TO_DOMAINS"
	PivotIPToServices       PivotKind = "IP_TO_SERVICES"
	PivotServiceToHosts     PivotKind = "SERVICE_TO_HOSTS"
	PivotCertificateToHosts PivotKind = "CERTIFICATE_TO_HOSTS"
	PivotHostToCertificates PivotKind = "HOST_TO_CERTIFICATES"
	PivotHostToTCPPorts     PivotKind = "HOST_TO_TCP_PORTS"
	PivotTCPPortToHosts     PivotKind = "TCP_PORT_TO_HOSTS"
	PivotHostToHTTPServices PivotKind = "HOST_TO_HTTP_SERVICES"
	PivotHTTPServiceToHosts PivotKind = "HTTP_SERVICE_TO_HOSTS"
)

// Pivot returns deterministic one-hop related nodes for a graph entity.
// Every result is backed by an existing graph edge; no relationship is inferred.
func Pivot(g Graph, nodeID string, kind PivotKind) ([]Node, error) {
	if err := validatePivotKind(kind); err != nil {
		return nil, err
	}
	if err := g.Validate(); err != nil {
		return nil, fmt.Errorf("validate graph before pivot: %w", err)
	}
	sourceNode, ok := findNode(g.Nodes, nodeID)
	if !ok {
		return nil, fmt.Errorf("pivot source node %q does not exist", nodeID)
	}

	// Index nodes once so traversal cost is linear in graph size rather than
	// repeatedly scanning all nodes for every edge.
	nodesByID := make(map[string]Node, len(g.Nodes))
	for _, node := range g.Nodes {
		nodesByID[node.ID] = node
	}
	nodeIDs := make(map[string]struct{})
	for _, edge := range g.Edges {
		source, sourceOK := nodesByID[edge.Source]
		target, targetOK := nodesByID[edge.Target]
		if !sourceOK || !targetOK {
			continue // Validate normally guarantees endpoints exist.
		}

		switch kind {
		case PivotDomainToIPs:
			if source.ID == nodeID && source.Type == NodeDomain && edge.Type == EdgeResolvesTo && target.Type == NodeIP {
				nodeIDs[target.ID] = struct{}{}
			}
		case PivotDomainToServices:
			if source.ID == nodeID && source.Type == NodeDomain && edge.Type == EdgeHostsService && target.Type == NodeNetworkService {
				nodeIDs[target.ID] = struct{}{}
			}
		case PivotIPToDomains:
			if target.ID == nodeID && target.Type == NodeIP && edge.Type == EdgeResolvesTo && source.Type == NodeDomain {
				nodeIDs[source.ID] = struct{}{}
			}
		case PivotIPToServices:
			if source.ID == nodeID && source.Type == NodeIP && edge.Type == EdgeHostsService && target.Type == NodeNetworkService {
				nodeIDs[target.ID] = struct{}{}
			}
		case PivotServiceToHosts:
			if target.ID == nodeID && target.Type == NodeNetworkService && edge.Type == EdgeHostsService && (source.Type == NodeDomain || source.Type == NodeIP) {
				nodeIDs[source.ID] = struct{}{}
			}
		case PivotCertificateToHosts:
			if target.ID == nodeID && target.Type == NodeTLSCertificate && edge.Type == EdgePresentsCertificate && (source.Type == NodeDomain || source.Type == NodeIP) {
				nodeIDs[source.ID] = struct{}{}
			}
		case PivotHostToCertificates:
			if source.ID == nodeID && (source.Type == NodeDomain || source.Type == NodeIP) && edge.Type == EdgePresentsCertificate && target.Type == NodeTLSCertificate {
				nodeIDs[target.ID] = struct{}{}
			}
		case PivotHostToTCPPorts:
			if source.ID == nodeID && (source.Type == NodeDomain || source.Type == NodeIP) && edge.Type == EdgeHasOpenPort && target.Type == NodeTCPPort {
				nodeIDs[target.ID] = struct{}{}
			}
		case PivotTCPPortToHosts:
			if target.ID == nodeID && target.Type == NodeTCPPort && edge.Type == EdgeHasOpenPort && (source.Type == NodeDomain || source.Type == NodeIP) {
				nodeIDs[source.ID] = struct{}{}
			}
		case PivotHostToHTTPServices:
			if source.ID == nodeID && (source.Type == NodeDomain || source.Type == NodeIP) && edge.Type == EdgeServesHTTP && target.Type == NodeHTTPService {
				nodeIDs[target.ID] = struct{}{}
			}
		case PivotHTTPServiceToHosts:
			if target.ID == nodeID && target.Type == NodeHTTPService && edge.Type == EdgeServesHTTP && (source.Type == NodeDomain || source.Type == NodeIP) {
				nodeIDs[source.ID] = struct{}{}
			}
		}
	}

	result := make([]Node, 0, len(nodeIDs))
	for id := range nodeIDs {
		result = append(result, nodesByID[id])
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

// Related returns all direct neighbors of a node through existing graph edges.
func Related(g Graph, nodeID string) ([]Node, error) {
	if err := g.Validate(); err != nil {
		return nil, fmt.Errorf("validate graph before related lookup: %w", err)
	}
	if _, ok := findNode(g.Nodes, nodeID); !ok {
		return nil, fmt.Errorf("related source node %q does not exist", nodeID)
	}

	nodesByID := make(map[string]Node, len(g.Nodes))
	for _, node := range g.Nodes {
		nodesByID[node.ID] = node
	}
	nodeIDs := make(map[string]struct{})
	for _, edge := range g.Edges {
		if edge.Source == nodeID {
			nodeIDs[edge.Target] = struct{}{}
		}
		if edge.Target == nodeID {
			nodeIDs[edge.Source] = struct{}{}
		}
	}

	result := make([]Node, 0, len(nodeIDs))
	for id := range nodeIDs {
		result = append(result, nodesByID[id])
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func validatePivotKind(kind PivotKind) error {
	switch kind {
	case PivotDomainToIPs,
		PivotDomainToServices,
		PivotIPToDomains,
		PivotIPToServices,
		PivotServiceToHosts,
		PivotCertificateToHosts,
		PivotHostToCertificates,
		PivotHostToTCPPorts,
		PivotTCPPortToHosts,
		PivotHostToHTTPServices,
		PivotHTTPServiceToHosts:
		return nil
	default:
		return fmt.Errorf("unsupported pivot kind %q", kind)
	}
}

func findNode(nodes []Node, id string) (Node, bool) {
	for _, node := range nodes {
		if node.ID == id {
			return node, true
		}
	}
	return Node{}, false
}
