package collectors

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

type fakeDNSResolver struct {
	addresses []net.IPAddr
	err       error
}

func (f *fakeDNSResolver) LookupIPAddr(
	ctx context.Context,
	host string,
) ([]net.IPAddr, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	return f.addresses, f.err
}

func TestDNSRunEmitsEvents(t *testing.T) {
	resolver := &fakeDNSResolver{
		addresses: []net.IPAddr{
			{IP: net.ParseIP("192.0.2.10")},
			{IP: net.ParseIP("192.0.2.11")},
		},
	}

	dns := &DNS{
		Resolver: resolver,
		Target:   "example.test",
		Timeout:  time.Second,
	}

	output := make(chan events.Event, 2)

	if err := dns.Run(context.Background(), output); err != nil {
		t.Fatalf("Run() returned an error: %v", err)
	}

	close(output)

	count := 0
	for event := range output {
		count++

		if err := event.Validate(); err != nil {
			t.Errorf("invalid event: %v", err)
		}

		if event.Target != "example.test" {
			t.Errorf("unexpected target: %q", event.Target)
		}

		if event.Source != "dns-collector" {
			t.Errorf("unexpected source: %q", event.Source)
		}

		if event.Type != events.EventDNSRecordFound {
			t.Errorf("unexpected event type: %q", event.Type)
		}

		if event.Data["value"] == "" {
			t.Error("event is missing IP address")
		}
	}

	if count != 2 {
		t.Errorf("got %d events, want 2", count)
	}
}

func TestDNSRunReturnsLookupError(t *testing.T) {
	dns := &DNS{
		Resolver: &fakeDNSResolver{
			err: errors.New("simulated DNS failure"),
		},
		Target: "example.test",
	}

	output := make(chan events.Event, 1)

	err := dns.Run(context.Background(), output)
	if err == nil {
		t.Fatal("Run() should return an error when DNS lookup fails")
	}
}

func TestDNSRunRejectsEmptyTarget(t *testing.T) {
	dns := &DNS{
		Target: "   ",
	}

	output := make(chan events.Event, 1)

	if err := dns.Run(context.Background(), output); err == nil {
		t.Fatal("Run() should reject an empty target")
	}
}

func TestDNSRunRejectsNilContext(t *testing.T) {
	dns := &DNS{Target: "example.test"}
	if err := dns.Run(nil, make(chan events.Event, 1)); err == nil {
		t.Fatal("Run() should reject a nil context")
	}
}
