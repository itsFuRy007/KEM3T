package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/itsFuRy007/kem3t/internal/graph"
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
