package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/graph"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
)

func TestRunHelpReturnsFlagHelp(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"kem3t", "-h"}
	defer func() {
		os.Args = oldArgs
	}()

	err := run()
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("run() error = %v, want flag.ErrHelp", err)
	}
}

func TestRunRejectsUnsupportedMode(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"kem3t", "-mode", "invalid"}
	defer func() {
		os.Args = oldArgs
	}()

	err := run()
	if err == nil {
		t.Fatal("expected unsupported mode error")
	}
	if !strings.Contains(err.Error(), `unsupported mode "invalid"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunDNSRequiresTarget(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"kem3t", "-mode", "dns"}
	defer func() {
		os.Args = oldArgs
	}()

	err := run()
	if err == nil {
		t.Fatal("expected missing target error")
	}
	if !strings.Contains(err.Error(), "-target is required in DNS mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrintInfrastructureGraph(t *testing.T) {
	g := graph.Graph{
		Nodes: []graph.Node{
			{ID: "domain:example.com", Type: graph.NodeDomain, Value: "example.com"},
			{ID: "ip:192.0.2.10", Type: graph.NodeIP, Value: "192.0.2.10"},
		},
		Edges: []graph.Edge{
			{
				ID:     "resolves-to:example.com:192.0.2.10",
				Type:   graph.EdgeResolvesTo,
				Source: "domain:example.com",
				Target: "ip:192.0.2.10",
			},
		},
	}

	oldStdout := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe() error = %v", err)
	}
	defer reader.Close()
	defer writer.Close()

	os.Stdout = writer
	defer func() {
		os.Stdout = oldStdout
	}()

	printInfrastructureGraph(g)
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close() error = %v", err)
	}

	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("reading captured output: %v", err)
	}
	if err := reader.Close(); err != nil {
		t.Fatalf("reader.Close() error = %v", err)
	}

	for _, expected := range []string{
		"[INFRASTRUCTURE GRAPH]",
		"Nodes: 2",
		"Relationships: 1",
		"[RESOLVES_TO] example.com -> 192.0.2.10",
	} {
		if !strings.Contains(string(output), expected) {
			t.Errorf("output missing %q; got:\n%s", expected, output)
		}
	}
}

func TestWriteInvestigationExport(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "investigation.json")
	report := intelligence.IntelligenceReport{Target: "example.com"}
	if err := writeInvestigationExport(path, intelligence.NewInvestigationExport("example.com", &report)); err != nil {
		t.Fatalf("writeInvestigationExport() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read export: %v", err)
	}
	var decoded intelligence.InvestigationExport
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode export: %v", err)
	}
	if decoded.SchemaVersion != intelligence.ExportSchemaVersion || decoded.Investigation.Target != "example.com" {
		t.Fatalf("unexpected export envelope: %#v", decoded)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat export: %v", err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("export permissions = %04o, want 0600", info.Mode().Perm())
	}
}

func TestWriteInvestigationExportRejectsMismatchedScope(t *testing.T) {
	path := filepath.Join(t.TempDir(), "investigation.json")
	err := writeInvestigationExport(path, intelligence.NewInvestigationExport("example.com", &intelligence.IntelligenceReport{Target: "other.example"}))
	if err == nil {
		t.Fatal("expected mismatched report scope to fail")
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("invalid export was written; stat error = %v", statErr)
	}
}

func TestRunRejectsExportOutsideDNSMode(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"kem3t", "-mode", "tls", "-target", "example.com", "-export-json", "report.json"}
	defer func() { os.Args = oldArgs }()
	err := run()
	if err == nil || !strings.Contains(err.Error(), "-export-json is supported only in DNS mode") {
		t.Fatalf("run() error = %v, want DNS-only export error", err)
	}
}

func TestCountTCPStatesSeparatesOpenClosedAndUnknown(t *testing.T) {
	input := []events.Event{
		{Data: map[string]string{"state": "open", "port": "80"}},
		{Data: map[string]string{"state": "closed", "port": "81"}},
		{Data: map[string]string{"state": "unknown", "port": "82"}},
		{Data: map[string]string{"state": "closed", "port": "83"}},
	}
	got, err := countTCPStates(input)
	if err != nil {
		t.Fatalf("countTCPStates() error = %v", err)
	}
	if got["open"] != 1 || got["closed"] != 2 || got["unknown"] != 1 {
		t.Fatalf("counts = %#v", got)
	}
}

func TestCountTCPStatesRejectsInvalidState(t *testing.T) {
	_, err := countTCPStates([]events.Event{{Data: map[string]string{"state": "filtered", "port": "80"}}})
	if err == nil {
		t.Fatal("expected unsupported TCP state to be rejected")
	}
}

func TestCountTCPStatesHandlesEmptyCollection(t *testing.T) {
	got, err := countTCPStates(nil)
	if err != nil {
		t.Fatalf("countTCPStates() error = %v", err)
	}
	if got["open"] != 0 || got["closed"] != 0 || got["unknown"] != 0 {
		t.Fatalf("empty collection counts = %#v", got)
	}
}

func TestCountTCPStatesNormalizesCaseAndWhitespace(t *testing.T) {
	input := []events.Event{
		{Data: map[string]string{"state": " OPEN ", "port": "80"}},
		{Data: map[string]string{"state": " Closed ", "port": "81"}},
	}
	got, err := countTCPStates(input)
	if err != nil {
		t.Fatalf("countTCPStates() error = %v", err)
	}
	if got["open"] != 1 || got["closed"] != 1 || got["unknown"] != 0 {
		t.Fatalf("normalized counts = %#v", got)
	}
}
