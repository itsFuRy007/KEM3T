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

// TCP scans an explicit range of TCP ports on one authorized target.
type TCP struct {
	Target      string
	StartPort   int
	EndPort     int
	Timeout     time.Duration
	Concurrency int
}

// Run emits one PORT_DISCOVERED event for each open TCP port.
func (c *TCP) Run(ctx context.Context, output chan<- events.Event) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}

	target := strings.TrimSpace(c.Target)
	if target == "" {
		return fmt.Errorf("TCP target is required")
	}
	if strings.Contains(target, "://") || strings.ContainsAny(target, "/?#") {
		return fmt.Errorf("TCP target must be a hostname or IP address, not a URL")
	}
	if c.StartPort < 1 || c.EndPort > 65535 || c.StartPort > c.EndPort {
		return fmt.Errorf("invalid TCP port range %d-%d", c.StartPort, c.EndPort)
	}

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	concurrency := c.Concurrency
	if concurrency <= 0 {
		concurrency = 20
	}
	if concurrency > 200 {
		concurrency = 200
	}

	type result struct {
		port int
		open bool
	}
	jobs := make(chan int)
	results := make(chan result, concurrency)
	workers := concurrency
	portCount := c.EndPort - c.StartPort + 1
	if workers > portCount {
		workers = portCount
	}

	for i := 0; i < workers; i++ {
		go func() {
			for port := range jobs {
				dialer := net.Dialer{Timeout: timeout}
				conn, err := dialer.DialContext(
					ctx,
					"tcp",
					net.JoinHostPort(target, strconv.Itoa(port)),
				)
				if err == nil {
					_ = conn.Close()
					select {
					case results <- result{port: port, open: true}:
					case <-ctx.Done():
					}
				} else {
					select {
					case results <- result{port: port, open: false}:
					case <-ctx.Done():
					}
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for port := c.StartPort; port <= c.EndPort; port++ {
			select {
			case jobs <- port:
			case <-ctx.Done():
				return
			}
		}
	}()

	go func() {
		// Workers finish after the job queue is closed.
		// Results are buffered so workers can exit if collection is cancelled.
	}()

	received := 0
	for received < portCount {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case item := <-results:
			received++
			if !item.open {
				continue
			}

			event := events.Event{
				ID:        fmt.Sprintf("tcp-%d-%d", time.Now().UTC().UnixNano(), item.port),
				Type:      events.EventPortDiscovered,
				Timestamp: time.Now().UTC(),
				Target:    target,
				Source:    "tcp-collector",
				Data: map[string]string{
					"protocol": "tcp",
					"port":     strconv.Itoa(item.port),
					"state":    "open",
				},
			}
			if err := event.Validate(); err != nil {
				return fmt.Errorf("create TCP event: %w", err)
			}

			select {
			case output <- event:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return nil
}
