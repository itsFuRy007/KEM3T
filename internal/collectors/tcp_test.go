package collectors

import (
	"context"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

func TestTCPFindsOpenPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	output := make(chan events.Event, 1)

	scanner := &TCP{
		Target:      "127.0.0.1",
		StartPort:   port,
		EndPort:     port,
		Timeout:     time.Second,
		Concurrency: 1,
	}

	if err := scanner.Run(context.Background(), output); err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	select {
	case event := <-output:
		if event.Type != events.EventPortDiscovered {
			t.Fatalf("unexpected event type: %s", event.Type)
		}
		if event.Data["port"] != strconv.Itoa(port) {
			t.Fatalf("unexpected port: %s", event.Data["port"])
		}
		if event.Data["state"] != "open" {
			t.Fatalf("unexpected state: %s", event.Data["state"])
		}
	default:
		t.Fatal("expected an open-port event")
	}
}

func TestTCPRejectsInvalidRange(t *testing.T) {
	scanner := &TCP{
		Target:    "127.0.0.1",
		StartPort: 9000,
		EndPort:   8000,
	}

	err := scanner.Run(context.Background(), make(chan events.Event, 1))
	if err == nil {
		t.Fatal("expected invalid port range error")
	}
}
