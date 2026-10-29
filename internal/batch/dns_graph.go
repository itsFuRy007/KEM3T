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


// DNSGraphChanges compares consecutive graph snapshots while avoiding false
// disappearance claims for targets that failed or were omitted from the new run.
type DNSGraphChanges struct {
	SchemaVersion             int           `json:"schema_version"`
	BaselineAvailable         bool          `json:"baseline_available"`
	BaselineGeneratedAt       time.Time     `json:"baseline_generated_at,omitempty"`
	CurrentGeneratedAt        time.Time     `json:"current_generated_at"`
	AddedResolutionEdges      []DNSGraphEdge `json:"added_resolution_edges"`
	NoLongerObservedEdges     []DNSGraphEdge `json:"no_longer_observed_edges"`
	AddedSharedAddressGroups  []string      `json:"added_shared_address_groups"`
	RemovedSharedAddressGroups []string     `json:"removed_shared_address_groups"`
	SkippedRemovalsForTargets []string      `json:"skipped_removals_for_targets"`
	Limitations               []string      `json:"limitations"`
}

// BuildDNSGraphChanges detects changes between consecutive DNS graph snapshots.
// A missing edge is only reported as no longer observed when that target was
// successfully investigated in the current run. Missing or failed scopes are
// explicitly skipped rather than misrepresented as negative DNS evidence.
func BuildDNSGraphChanges(previous *DNSInvestigationGraph, current DNSInvestigationGraph) DNSGraphChanges {
	changes := DNSGraphChanges{
		SchemaVersion: DNSGraphSchemaVersion,
		CurrentGeneratedAt: current.GeneratedAt,
		AddedResolutionEdges: make([]DNSGraphEdge, 0),
		NoLongerObservedEdges: make([]DNSGraphEdge, 0),
		AddedSharedAddressGroups: make([]string, 0),
		RemovedSharedAddressGroups: make([]string, 0),
		SkippedRemovalsForTargets: make([]string, 0),
		Limitations: []string{
			"DNS relationship changes compare collection snapshots; they do not prove infrastructure ownership, causation, or malicious activity.",
			"A relationship absent from a snapshot means it was not observed in that run, not necessarily that it ceased to exist globally.",
			"Missing or failed target scopes are excluded from disappearance claims.",
		},
	}
	if previous == nil {
		return changes
	}
	changes.BaselineAvailable = true
	changes.BaselineGeneratedAt = previous.GeneratedAt

	previousEdges := make(map[string]DNSGraphEdge)
	currentEdges := make(map[string]DNSGraphEdge)
	currentTargetStatus := make(map[string]string)
	previousClusters := make(map[string]struct{})
	currentClusters := make(map[string]struct{})
	previousClusterMembers := make(map[string]map[string]struct{})
	skippedTargets := make(map[string]struct{})

	for _, edge := range previous.Edges {
		previousEdges[edge.ID] = edge
		if edge.Type == "MEMBER_OF_SHARED_ADDRESS_CORRELATION" {
			if previousClusterMembers[edge.Target] == nil {
				previousClusterMembers[edge.Target] = make(map[string]struct{})
			}
			if strings.HasPrefix(edge.Source, "target:") {
				previousClusterMembers[edge.Target][strings.TrimPrefix(edge.Source, "target:")] = struct{}{}
			}
		}
	}
	for _, edge := range current.Edges {
		currentEdges[edge.ID] = edge
	}
	for _, node := range previous.Nodes {
		if node.Type == "SHARED_ADDRESS_CORRELATION" {
			previousClusters[node.ID] = struct{}{}
		}
	}
	for _, node := range current.Nodes {
		if node.Type == "TARGET_SCOPE" {
			currentTargetStatus[node.Value] = node.Status
		}
		if node.Type == "SHARED_ADDRESS_CORRELATION" {
			currentClusters[node.ID] = struct{}{}
		}
	}

	for id, edge := range currentEdges {
		if edge.Type == "OBSERVED_DNS_RESOLUTION" {
			if _, existed := previousEdges[id]; !existed {
				changes.AddedResolutionEdges = append(changes.AddedResolutionEdges, edge)
			}
		}
	}
	for id, edge := range previousEdges {
		if edge.Type != "OBSERVED_DNS_RESOLUTION" {
			continue
		}
		if _, stillObserved := currentEdges[id]; stillObserved {
			continue
		}
		target := strings.TrimPrefix(edge.Source, "target:")
		if currentTargetStatus[target] == "SUCCESS" {
			changes.NoLongerObservedEdges = append(changes.NoLongerObservedEdges, edge)
		} else {
			skippedTargets[target] = struct{}{}
		}
	}

	for clusterID := range currentClusters {
		if _, existed := previousClusters[clusterID]; !existed {
			changes.AddedSharedAddressGroups = append(changes.AddedSharedAddressGroups, strings.TrimPrefix(clusterID, "correlation:shared-address:"))
		}
	}
	for clusterID := range previousClusters {
		if _, remains := currentClusters[clusterID]; remains {
			continue
		}
		members := previousClusterMembers[clusterID]
		canClaimNoLongerObserved := len(members) > 0
		for target := range members {
			if currentTargetStatus[target] != "SUCCESS" {
				canClaimNoLongerObserved = false
				skippedTargets[target] = struct{}{}
			}
		}
		if canClaimNoLongerObserved {
			changes.RemovedSharedAddressGroups = append(changes.RemovedSharedAddressGroups, strings.TrimPrefix(clusterID, "correlation:shared-address:"))
		}
	}

	for target := range skippedTargets {
		changes.SkippedRemovalsForTargets = append(changes.SkippedRemovalsForTargets, target)
	}
	sort.Slice(changes.AddedResolutionEdges, func(i, j int) bool { return changes.AddedResolutionEdges[i].ID < changes.AddedResolutionEdges[j].ID })
	sort.Slice(changes.NoLongerObservedEdges, func(i, j int) bool { return changes.NoLongerObservedEdges[i].ID < changes.NoLongerObservedEdges[j].ID })
	sort.Strings(changes.AddedSharedAddressGroups)
	sort.Strings(changes.RemovedSharedAddressGroups)
	sort.Strings(changes.SkippedRemovalsForTargets)
	return changes
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
		// Each target scope is accepted once and each address is deduplicated
		// within that scope above, so refs already contains unique targets.
		if len(refs) < 2 {
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
		for _, ref := range refs {
			targetID := "target:" + ref.Target
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
	graphPath := filepath.Join(dir, "investigation-graph.json")
	var previous *DNSInvestigationGraph
	var previousData []byte
	if data, err := os.ReadFile(graphPath); err == nil {
		var decoded DNSInvestigationGraph
		if err := json.Unmarshal(data, &decoded); err != nil {
			return fmt.Errorf("decode previous DNS graph: %w", err)
		}
		previous = &decoded
		previousData = data
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("read previous DNS graph: %w", err)
	}

	changes := BuildDNSGraphChanges(previous, graph)
	changeData, err := json.MarshalIndent(changes, "", "  ")
	if err != nil {
		return fmt.Errorf("encode DNS graph changes: %w", err)
	}
	changeData = append(changeData, byte(10))

	graphData, err := json.MarshalIndent(graph, "", "  ")
	if err != nil {
		return fmt.Errorf("encode DNS investigation graph: %w", err)
	}
	graphData = append(graphData, byte(10))

	historyDir := filepath.Join(dir, "history")
	if err := os.MkdirAll(historyDir, 0750); err != nil {
		return fmt.Errorf("create graph history directory: %w", err)
	}
	if previous != nil {
		if err := archiveGraph(historyDir, previous.GeneratedAt, previousData); err != nil {
			return fmt.Errorf("archive previous DNS graph: %w", err)
		}
	}
	if err := archiveGraph(historyDir, graph.GeneratedAt, graphData); err != nil {
		return fmt.Errorf("archive current DNS graph: %w", err)
	}
	if err := writeAtomicFile(dir, "graph-changes.json", changeData, ".changes-*.tmp"); err != nil {
		return fmt.Errorf("persist DNS graph changes: %w", err)
	}
	if err := writeAtomicFile(dir, "investigation-graph.json", graphData, ".graph-*.tmp"); err != nil {
		return fmt.Errorf("persist DNS investigation graph: %w", err)
	}
	return nil
}

func archiveGraph(historyDir string, generatedAt time.Time, data []byte) error {
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	name := "graph-" + generatedAt.UTC().Format("20060102T150405.000000000Z") + ".json"
	if _, err := os.Stat(filepath.Join(historyDir, name)); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	return writeAtomicFile(historyDir, name, data, ".history-*.tmp")
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
