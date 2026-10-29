package graph

import (
	"fmt"
	"sort"
)

// PivotKind identifies a supported one-hop investigation pivot. Pivots only
// traverse relationships already present in the evidence-backed graph; they
// never infer new infrastructure facts.
type PivotKind string

const (
	PivotDomainToIPs        PivotKind = "DOMAIN_TO_IPS"
	PivotDomainToServices   PivotKind = "DOMAIN_TO_SERVICES"
	PivotIPToDomains        PivotKind = "IP_TO_DOMAINS"
	PivotIPToServices       PivotKind = "IP_TO_SERVICES"
	PivotServiceToHosts     PivotKind = "SERVICE_TO_HOSTS"
	PivotCertificateToHosts PivotKind = "CERTIFICATE_TO_HOSTS"
	PivotHostToCertificates PivotKind = "HOST_TO_CERTIFICATES"
)

// Pivot returns deterministic one-hop related nodes for a graph entity.
// Every result is backed by an existing graph edge and therefore retains the
// graph's evidence boundary. No new relationship is inferred by this API.
func Pivot(g Graph, nodeID string, kind PivotKind) ([]Node, error) {
	if err := g.Validate(); err != nil {
		return nil, fmt.Errorf("validate graph before pivot: %w", err)
	}
	if _, ok := findNode(g.Nodes, nodeID); !ok {
		return nil, fmt.Errorf("pivot source node %q does not exist", nodeID)
	}

	nodeIDs := make(map[string]struct{})
	for _, edge := range g.Edges {
		source, _ := findNode(g.Nodes, edge.Source)
		target, _ := findNode(g.Nodes, edge.Target)

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
		default:
			return nil, fmt.Errorf("unsupported pivot kind %q", kind)
		}
	}

	result := make([]Node, 0, len(nodeIDs))
	for id := range nodeIDs {
		node, ok := findNode(g.Nodes, id)
		if ok {
			result = append(result, node)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

// Related returns all direct neighbors of a node. It traverses both incoming
// and outgoing evidence-backed relationships without inventing new edges.
func Related(g Graph, nodeID string) ([]Node, error) {
	if err := g.Validate(); err != nil {
		return nil, fmt.Errorf("validate graph before related lookup: %w", err)
	}
	if _, ok := findNode(g.Nodes, nodeID); !ok {
		return nil, fmt.Errorf("related source node %q does not exist", nodeID)
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
		node, ok := findNode(g.Nodes, id)
		if ok {
			result = append(result, node)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result, nil
}

func findNode(nodes []Node, id string) (Node, bool) {
	for _, node := range nodes {
		if node.ID == id {
			return node, true
		}
	}
	return Node{}, false
}
