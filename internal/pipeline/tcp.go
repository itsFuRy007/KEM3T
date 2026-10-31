package pipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/graph"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/investigation"
	"github.com/itsFuRy007/kem3t/internal/observations"
)

type TCPResult struct {
	Events           []events.Event
	Findings         []intelligence.Finding
	Report           intelligence.IntelligenceReport
	Evidence         []evidence.Evidence
	Observations     []evidence.Observation
	EvidenceRegistry *evidence.Registry
	Graph            graph.Graph
	Normalized       observations.Collection
}

// RunTCP preserves the original pipeline API while delegating execution and
// persistence to the shared investigation engine.
func RunTCP(ctx context.Context, target string, startPort, endPort int, snapshotDir string) (result TCPResult, retErr error) {
	if startPort < 1 || endPort > 65535 || startPort > endPort {
		return TCPResult{}, fmt.Errorf("invalid TCP port range")
	}
	unified, registry, err := runUnifiedStage(ctx, target, snapshotDir, investigation.NewTCPStage(target, startPort, endPort))
	if registry != nil {
		result.EvidenceRegistry = registry
		defer func() {
			if closeErr := registry.Close(); closeErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("close shared evidence registry: %w", closeErr))
			}
		}()
	}
	if len(unified.Stages) > 0 {
		stage := unified.Stages[0].Result
		result.Events = stage.CollectedEvents
		result.Findings = stage.Findings
		result.Evidence = stage.EvidenceRecords
		result.Observations = stage.ObservationRecords
	}
	result.Report = unified.Report
	result.Graph = unified.Graph
	result.Normalized = unified.Normalized
	if err != nil {
		return result, err
	}
	if strings.TrimSpace(result.Report.Target) == "" {
		return result, fmt.Errorf("unified investigation did not produce an intelligence report")
	}
	return result, nil
}
