package integration

import (
	"context"
	"net"
	"strconv"
	"testing"

	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/pipeline"
)

func TestTCPPipelineEndToEndLocalhost(t *testing.T) {
	// Open a local TCP listener so the test has a known-open port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("start local TCP listener: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	result, err := pipeline.RunTCP(
		context.Background(),
		"127.0.0.1",
		port,
		port,
		t.TempDir(),
	)
	if err != nil {
		t.Fatalf("RunTCP: %v", err)
	}

	// Verify the collector -> pipeline -> evidence path.
	if len(result.Events) != 1 {
		t.Fatalf("expected 1 open-port event, got %d", len(result.Events))
	}
	event := result.Events[0]

	if event.Type != events.EventPortDiscovered {
		t.Fatalf("expected PORT_DISCOVERED, got %q", event.Type)
	}
	if event.Target != "127.0.0.1" {
		t.Fatalf("unexpected target: %q", event.Target)
	}
	if event.Data["protocol"] != "tcp" ||
		event.Data["port"] != strconv.Itoa(port) ||
		event.Data["state"] != "open" {
		t.Fatalf("unexpected TCP event data: %#v", event.Data)
	}

	if len(result.Evidence) != 1 {
		t.Fatalf("expected 1 evidence record, got %d", len(result.Evidence))
	}
	if len(result.Observations) != 1 {
		t.Fatalf("expected 1 observation, got %d", len(result.Observations))
	}

	// Verify that the intelligence engine can analyze the collected event.
	engine := &intelligence.Engine{}
	finding, err := engine.Analyze(event)
	if err != nil {
		t.Fatalf("analyze TCP event: %v", err)
	}
	if finding == nil {
		t.Fatal("expected a finding for the open TCP port")
	}

	// Verify that the pipeline built a valid graph.
	if err := result.Graph.Validate(); err != nil {
		t.Fatalf("validate result graph: %v", err)
	}
	if len(result.Graph.Nodes) == 0 {
		t.Fatal("expected graph nodes")
	}
	if len(result.Graph.Edges) == 0 {
		t.Fatal("expected graph edges")
	}
}
