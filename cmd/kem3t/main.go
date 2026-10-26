package main

import (
	"context"
	"fmt"
	"log"

	"github.com/itsFuRy007/kem3t/internal/collectors"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
)

func main() {
	ctx := context.Background()

	eventCh := make(chan events.Event)
	findingCh := make(chan intelligence.Finding)

	engine := &intelligence.Engine{}
	collector := &collectors.Demo{}

	go func() {
		defer close(findingCh)
		if err := engine.Run(ctx, eventCh, findingCh); err != nil {
			log.Printf("Engine error: %v", err)
		}
	}()

	go func() {
		defer close(eventCh)
		if err := collector.Run(ctx, eventCh); err != nil {
			log.Printf("Collector error: %v", err)
		}
	}()

	for finding := range findingCh {
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
}
