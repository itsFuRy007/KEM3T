package collectors

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

// DNSResolver allows DNS lookups to be replaced in tests.
type DNSResolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// DNS collects resolved IP addresses for a target hostname.
type DNS struct {
	Resolver DNSResolver
	Target   string
	Timeout  time.Duration
}

// Run resolves the target and emits one event per IP address.
func (d *DNS) Run(ctx context.Context, output chan<- events.Event) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	target := strings.TrimSpace(d.Target)
	if target == "" {
		return fmt.Errorf("DNS target is required")
	}

	resolver := d.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	timeout := d.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	lookupCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	addresses, err := resolver.LookupIPAddr(lookupCtx, target)
	if err != nil {
		return fmt.Errorf("resolve %q: %w", target, err)
	}

	if len(addresses) == 0 {
		return fmt.Errorf("no IP addresses found for %q", target)
	}

	for i, address := range addresses {
		ip := address.IP.String()
		if ip == "" {
			continue
		}

		event := events.Event{
			ID:        "dns-" + strconv.FormatInt(time.Now().UnixNano(), 10) + "-" + strconv.Itoa(i),
			Type:      events.EventDNSRecordFound,
			Timestamp: time.Now().UTC(),
			Target:    target,
			Source:    "dns-collector",
			Data: map[string]string{
				"record_type": "IP_ADDRESS",
				"value":       ip,
			},
		}

		if err := event.Validate(); err != nil {
			return fmt.Errorf("create DNS event: %w", err)
		}

		select {
		case output <- event:
		case <-ctx.Done():
			return ctx.Err()
		case <-lookupCtx.Done():
			return lookupCtx.Err()
		}
	}

	return nil
}
