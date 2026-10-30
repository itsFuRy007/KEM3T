package collectors

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

type TCP struct {
	Target      string
	StartPort   int
	EndPort     int
	Timeout     time.Duration
	Concurrency int
}

type tcpPortResult struct {
	port   int
	state  string
	reason string
}

// Run emits one event for every scanned TCP port. OPEN is represented by
// PORT_DISCOVERED; CLOSED and UNKNOWN are represented by TCP_PORT_STATE_OBSERVED.
// A simple connect scan deliberately does not claim FILTERED because it cannot
// distinguish filtering from other inconclusive network failures.
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

	portCount := c.EndPort - c.StartPort + 1
	workers := concurrency
	if workers > portCount {
		workers = portCount
	}

	jobs := make(chan int)
	results := make(chan tcpPortResult, workers)
	workerDone := make(chan struct{})

	var workersWG sync.WaitGroup
	workersWG.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer workersWG.Done()
			for port := range jobs {
				state, reason := dialTCP(ctx, target, port, timeout)
				select {
				case results <- tcpPortResult{port: port, state: state, reason: reason}:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	go func() {
		workersWG.Wait()
		close(workerDone)
		close(results)
	}()

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

	received := 0
	for received < portCount {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case item, ok := <-results:
			if !ok {
				return fmt.Errorf("TCP workers stopped before all ports were classified: received %d of %d", received, portCount)
			}
			received++

			timestamp := time.Now().UTC()
			eventType := events.EventTCPPortStateObserved
			if item.state == "open" {
				eventType = events.EventPortDiscovered
			}
			data := map[string]string{
				"protocol": "tcp",
				"port":     strconv.Itoa(item.port),
				"state":    item.state,
			}
			if item.reason != "" {
				data["reason"] = item.reason
			}
			event := events.Event{
				ID:        fmt.Sprintf("tcp-%d-%d", timestamp.UnixNano(), item.port),
				Type:      eventType,
				Timestamp: timestamp,
				Target:    target,
				Source:    "tcp-collector",
				Data:      data,
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

	<-workerDone
	return nil
}

func dialTCP(ctx context.Context, target string, port int, timeout time.Duration) (string, string) {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(target, strconv.Itoa(port)))
	if err == nil {
		_ = conn.Close()
		return "open", ""
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return "closed", "connection refused"
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return "unknown", "timeout"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "unknown", "timeout"
	}
	if errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.ENETUNREACH) {
		return "unknown", "host or network unreachable"
	}
	if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
		return "unknown", "permission denied"
	}
	return "unknown", "connection attempt inconclusive: " + err.Error()
}
