package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/collectors"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
)

type Collector interface {
	Run(context.Context, chan<- events.Event) error
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	mode := flag.String("mode", "demo", "Collector mode: demo or dns")
	target := flag.String("target", "", "Target hostname for DNS mode")
	flag.Parse()

	var collector Collector

	switch strings.ToLower(*mode) {
	case "demo":
		collector = &collectors.Demo{}

	case "dns":
		if strings.TrimSpace(*target) == "" {
			return fmt.Errorf("-target is required in DNS mode")
		}
		collector = &collectors.DNS{Target: *target}

	default:
		return fmt.Errorf("unsupported mode %q", *mode)
	}

	ctx := context.Background()
	eventCh := make(chan events.Event)
	collectorErr := make(chan error, 1)

	go func() {
		defer close(eventCh)
		collectorErr <- collector.Run(ctx, eventCh)
	}()

	if strings.EqualFold(*mode, "dns") {
		aggregator := intelligence.NewAggregator()

		for event := range eventCh {
			if err := aggregator.Add(event); err != nil {
				return fmt.Errorf("aggregate event: %w", err)
			}
		}

		if err := <-collectorErr; err != nil {
			return fmt.Errorf("collector failed: %w", err)
		}

		findings := aggregator.Findings()
		if len(findings) == 0 {
			return fmt.Errorf("DNS collector produced no findings")
		}

		for _, finding := range findings {
			printFinding(finding)
		}
		return nil
	}

	findingCh := make(chan intelligence.Finding)
	engine := &intelligence.Engine{}

	go func() {
		defer close(findingCh)
		_ = engine.Run(ctx, eventCh, findingCh)
	}()

	for finding := range findingCh {
		printFinding(finding)
	}

	if err := <-collectorErr; err != nil {
		return fmt.Errorf("collector failed: %w", err)
	}

	return nil
}

func printFinding(finding intelligence.Finding) {
	fmt.Printf("\n[%s] %s\n", finding.Priority, finding.Title)
	fmt.Printf("Fact: %s\n", finding.Fact)

	if finding.Observation != "" {
		fmt.Printf("Observation: %s\n", finding.Observation)
	}

	if finding.PossibleSignificance != "" {
		fmt.Printf("Possible significance: %s\n", finding.PossibleSignificance)
	}

	fmt.Println("Next steps:")
	for _, step := range finding.NextSteps {
		fmt.Printf("  - %s\n", step)
	}

	fmt.Printf("Evidence events: %d\n", len(finding.Evidence))
}
