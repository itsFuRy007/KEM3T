package batch

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const DNSGraphSchemaVersion = 1

// DNSInvestigationGraph is a portable, deterministic graph projection of a
// batch DNS run. It retains observation timestamps and evidence-store references
// so consumers can trace each edge back to the original per-target evidence.
type DNSInvestigationGraph struct {
	SchemaVersion int                `json:"schema_version"`
	GeneratedAt   time.Time          `json:"generated_at"`
	Summary       DNSGraphSummary    `json:"summary"`
	Nodes         []DNSGraphNode     `json:"nodes"`
	Edges         []DNSGraphEdge     `json:"edges"`
	Limitations   []string           `json:"limitations"`
}

type DNSGraphSummary struct {
	TargetScopes        int `json:"target_scopes"`
	SuccessfulTargets   int `json:"successful_targets"`
	FailedTargets       int `json:"failed_targets"`
	UniqueAddresses     int `json:"unique_addresses"`
	AddressObservations int `json:"address_observations"`
	SharedAddressGroups int `json:"shared_address_groups"`
}

type DNSGraphNode struct {
	ID     string `json:"id"`
	Type   string `json:"type"`
	Value  string `json:"value"`
	Status string `json:"status,omitempty"`
	Error  string `json:"error,omitempty"`
}

type DNSGraphEdge struct {
	ID             string    `json:"id"`
	Type           string    `json:"type"`
	Source         string    `json:"source"`
	Target         string    `json:"target"`
	ObservedAt     time.Time `json:"observed_at,omitempty"`
	EvidenceStore  string    `json:"evidence_store,omitempty"`
	Interpretation string    `json:"interpretation,omitempty"`
}

// BuildDNSInvestigationGraph creates an evidence-traceable graph from successful
// DNS observations and retains failed scopes as failed target nodes. Shared IPs
// are represented by bounded-size cluster nodes, not pairwise target cliques.
func BuildDNSInvestigationGraph(outcomes []DNSOutcome, generatedAt time.Time) DNSInvestigationGraph {
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	} else {
		generatedAt = generatedAt.UTC()
	}
	graph := DNSInvestigationGraph{
		SchemaVersion: DNSGraphSchemaVersion,
		GeneratedAt: generatedAt,
		Nodes: make([]DNSGraphNode, 0),
		Edges: make([]DNSGraphEdge, 0),
		Limitations: []string{
			"Observed DNS resolution is time-scoped and does not guarantee current resolution.",
			"A shared address is a correlation lead only; CDNs, shared hosting, reverse proxies, cloud platforms, and unrelated tenants can share an IP.",
			"Failed target scopes are retained but produce no negative-resolution edges.",
			"Evidence-store paths are local references from the machine that ran KEM3T; consumers on another machine may not be able to open them.",
		},
	}
	nodes := make(map[string]DNSGraphNode)
	edges := make(map[string]DNSGraphEdge)
	targetAddresses := make(map[string]map[string]DNSObservationRef)
	addressTargets := make(map[string][]DNSObservationRef)
	targetSeen := make(map[string]struct{})

	for _, outcome := range outcomes {
		target := strings.TrimSpace(outcome.Target)
		if target == "" {
			continue
		}
		if _, exists := targetSeen[target]; exists {
			continue
		}
		targetSeen[target] = struct{}{}
		status := "SUCCESS"
		if outcome.Err != nil || outcome.Error != "" {
			status = "FAILED"
			graph.Summary.FailedTargets++
		} else {
			graph.Summary.SuccessfulTargets++
		}
		targetID := "target:" + target
		nodes[targetID] = DNSGraphNode{ID: targetID, Type: "TARGET_SCOPE", Value: target, Status: status}
		if status == "FAILED" {
			if outcome.Error != "" {
				node := nodes[targetID]
				node.Error = outcome.Error
				nodes[targetID] = node
			} else if outcome.Err != nil {
				node := nodes[targetID]
				node.Error = outcome.Err.Error()
				nodes[targetID] = node
			}
			continue
		}

		if targetAddresses[target] == nil {
			targetAddresses[target] = make(map[string]DNSObservationRef)
		}
		seenForTarget := make(map[string]struct{})
		for _, raw := range outcome.Addresses {
			ip := net.ParseIP(strings.TrimSpace(raw))
			if ip == nil {
				continue
			}
			address := ip.String()
			if _, exists := seenForTarget[address]; exists {
				continue
			}
			seenForTarget[address] = struct{}{}
			ref := DNSObservationRef{Target: target, CollectedAt: outcome.CollectedAt, EvidenceStore: outcome.EvidenceStore}
			targetAddresses[target][address] = ref
			addressTargets[address] = append(addressTargets[address], ref)
			ipID := "ip:" + address
			nodes[ipID] = DNSGraphNode{ID: ipID, Type: "IP_ADDRESS", Value: address}
			edgeID := "observed-dns-resolution:" + target + ":" + address
			edges[edgeID] = DNSGraphEdge{
				ID: edgeID, Type: "OBSERVED_DNS_RESOLUTION", Source: targetID, Target: ipID,
				ObservedAt: outcome.CollectedAt, EvidenceStore: outcome.EvidenceStore,
				Interpretation: "Observed during this collection; not a guarantee of current resolution.",
			}
			graph.Summary.AddressObservations++
		}
	}

	for address, refs := range addressTargets {
		uniqueTargets := make(map[string]DNSObservationRef)
		for _, ref := range refs {
			uniqueTargets[ref.Target] = ref
		}
		if len(uniqueTargets) < 2 {
			continue
		}
		graph.Summary.SharedAddressGroups++
		ipID := "ip:" + address
		clusterID := "correlation:shared-address:" + address
		nodes[clusterID] = DNSGraphNode{
			ID: clusterID, Type: "SHARED_ADDRESS_CORRELATION", Value: address,
			Status: "INVESTIGATION_LEAD",
		}
		clusterEdgeID := "correlation-address:" + address
		edges[clusterEdgeID] = DNSGraphEdge{
			ID: clusterEdgeID, Type: "CORRELATION_REFERENCES_ADDRESS", Source: clusterID, Target: ipID,
			Interpretation: "The cluster groups target scopes observed resolving to this address; it does not assert common ownership.",
		}
		for target, ref := range uniqueTargets {
			targetID := "target:" + target
			edgeID := "member-of-shared-address-correlation:" + address + ":" + target
			edges[edgeID] = DNSGraphEdge{
				ID: edgeID, Type: "MEMBER_OF_SHARED_ADDRESS_CORRELATION", Source: targetID, Target: clusterID,
				ObservedAt: ref.CollectedAt, EvidenceStore: ref.EvidenceStore,
				Interpretation: "Target was observed resolving to the clustered address; investigate as a lead, not proof of control.",
			}
		}
	}

	graph.Summary.TargetScopes = len(targetSeen)
	graph.Summary.UniqueAddresses = len(addressTargets)
	for _, node := range nodes {
		graph.Nodes = append(graph.Nodes, node)
	}
	for _, edge := range edges {
		graph.Edges = append(graph.Edges, edge)
	}
	sort.Slice(graph.Nodes, func(i, j int) bool { return graph.Nodes[i].ID < graph.Nodes[j].ID })
	sort.Slice(graph.Edges, func(i, j int) bool { return graph.Edges[i].ID < graph.Edges[j].ID })
	return graph
}

// PersistDNSInvestigationGraph atomically writes a portable graph JSON file.
func PersistDNSInvestigationGraph(snapshotDir string, outcomes []DNSOutcome, generatedAt time.Time) error {
	snapshotDir = strings.TrimSpace(snapshotDir)
	if snapshotDir == "" {
		return fmt.Errorf("snapshot directory is required")
	}
	dir := filepath.Join(snapshotDir, "batch-dns")
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create graph directory: %w", err)
	}
	graph := BuildDNSInvestigationGraph(outcomes, generatedAt)
	data, err := json.MarshalIndent(graph, "", "  ")
	if err != nil {
		return fmt.Errorf("encode DNS investigation graph: %w", err)
	}
	data = append(data, '
')
	return writeAtomicFile(dir, "investigation-graph.json", data, ".graph-*.tmp")
}

func writeAtomicFile(dir, name string, data []byte, pattern string) error {
	temp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return fmt.Errorf("create temporary file: %w", err)
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return fmt.Errorf("write temporary file: %w", err)
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return fmt.Errorf("sync temporary file: %w", err)
	}
	if err := temp.Close(); err != nil {
		return fmt.Errorf("close temporary file: %w", err)
	}
	if err := os.Rename(tempPath, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("replace file: %w", err)
	}
	return nil
}
