package batch

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestBuildDNSInvestigationGraphPreservesProvenanceAndClustersWithoutClique(t *testing.T) {
	when := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	outcomes := []DNSOutcome{
		{Target: "a.example", Addresses: []string{"192.0.2.10", "192.0.2.10", "bad-ip"}, CollectedAt: when, EvidenceStore: "/evidence/a.db"},
		{Target: "b.example", Addresses: []string{"192.0.2.10", "2001:db8::1"}, CollectedAt: when.Add(time.Minute), EvidenceStore: "/evidence/b.db"},
		{Target: "failed.example", Error: "timeout", Err: errors.New("timeout"), Addresses: []string{"192.0.2.10"}},
	}
	graph := BuildDNSInvestigationGraph(outcomes, when)
	if graph.SchemaVersion != DNSGraphSchemaVersion {
		t.Fatalf("schema version=%d", graph.SchemaVersion)
	}
	if graph.Summary.TargetScopes != 3 || graph.Summary.SuccessfulTargets != 2 || graph.Summary.FailedTargets != 1 {
		t.Fatalf("unexpected summary: %+v", graph.Summary)
	}
	if graph.Summary.UniqueAddresses != 2 || graph.Summary.AddressObservations != 3 || graph.Summary.SharedAddressGroups != 1 {
		t.Fatalf("unexpected address summary: %+v", graph.Summary)
	}
	if len(graph.Nodes) != 6 || len(graph.Edges) != 6 {
		t.Fatalf("unexpected graph size: nodes=%d edges=%d", len(graph.Nodes), len(graph.Edges))
	}
	var resolutionFound, clusterFound, failedFound bool
	for _, edge := range graph.Edges {
		if edge.Type == "OBSERVED_DNS_RESOLUTION" && edge.Source == "target:a.example" && edge.Target == "ip:192.0.2.10" {
			resolutionFound = true
			if edge.EvidenceStore != "/evidence/a.db" || !edge.ObservedAt.Equal(when) {
				t.Fatalf("resolution provenance missing: %+v", edge)
			}
		}
		if edge.Type == "MEMBER_OF_SHARED_ADDRESS_CORRELATION" {
			clusterFound = true
			if !strings.Contains(edge.Interpretation, "not proof") {
				t.Fatalf("correlation caveat missing: %+v", edge)
			}
		}
		if edge.Source == "target:failed.example" {
			failedFound = true
		}
	}
	for _, node := range graph.Nodes {
		if node.ID == "target:failed.example" && node.Status == "FAILED" && node.Error == "timeout" {
			failedFound = true
		}
	}
	if !resolutionFound || !clusterFound || !failedFound {
		t.Fatalf("missing expected graph content: resolution=%t cluster=%t failed=%t", resolutionFound, clusterFound, failedFound)
	}
	if got := len(graph.Edges); got >= 10 {
		t.Fatalf("expected shared-address cluster representation to avoid pairwise clique growth, got %d edges", got)
	}
}

func TestBuildDNSInvestigationGraphIsDeterministic(t *testing.T) {
	when := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	outcomes := []DNSOutcome{
		{Target: "z.example", Addresses: []string{"192.0.2.2", "192.0.2.1"}, CollectedAt: when},
		{Target: "a.example", Addresses: []string{"192.0.2.1"}, CollectedAt: when},
	}
	first, err := json.Marshal(BuildDNSInvestigationGraph(outcomes, when))
	if err != nil {
		t.Fatal(err)
	}
	second, err := json.Marshal(BuildDNSInvestigationGraph(outcomes, when))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatal("graph serialization changed between identical builds")
	}
}

func TestPersistDNSBatchReportWritesGraphAndReferencesIt(t *testing.T) {
	dir := t.TempDir()
	outcomes := []DNSOutcome{
		{Target: "a.example", Addresses: []string{"192.0.2.1"}},
		{Target: "b.example", Addresses: []string{"192.0.2.1"}},
	}
	if err := PersistDNSBatchReport(dir, outcomes); err != nil {
		t.Fatal(err)
	}
	reportPath := filepath.Join(dir, "batch-dns", "report.json")
	reportData, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	var report DNSBatchReport
	if err := json.Unmarshal(reportData, &report); err != nil {
		t.Fatal(err)
	}
	if report.GraphFile != "investigation-graph.json" {
		t.Fatalf("report graph reference=%q", report.GraphFile)
	}
	graphPath := filepath.Join(dir, "batch-dns", report.GraphFile)
	graphData, err := os.ReadFile(graphPath)
	if err != nil {
		t.Fatal(err)
	}
	var graph DNSInvestigationGraph
	if err := json.Unmarshal(graphData, &graph); err != nil {
		t.Fatal(err)
	}
	if graph.Summary.SharedAddressGroups != 1 {
		t.Fatalf("graph missing shared-address cluster: %+v", graph.Summary)
	}
}
