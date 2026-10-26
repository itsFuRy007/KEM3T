package collectors

import (
	"context"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

// Demo emits sample events to test the pipeline.
// It does not perform network reconnaissance.
type Demo struct{}

func (d *Demo) Run(ctx context.Context, output chan<- events.Event) error {
	samples := []events.Event{
		{
			ID:        "demo-001",
			Type:      events.EventSubdomainDiscovered,
			Timestamp: time.Now().UTC(),
			Target:    "dev.example.com",
			Source:    "demo-collector",
		},
		{
			ID:        "demo-002",
			Type:      events.EventSubdomainDiscovered,
			Timestamp: time.Now().UTC(),
			Target:    "api.example.com",
			Source:    "demo-collector",
		},
	}

	for _, event := range samples {
		select {
		case output <- event:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}
