package pipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/graph"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/investigation"
	"github.com/itsFuRy007/kem3t/internal/observations"
)

type TLSResult struct {
	Event            *events.Event
	Evidence         evidence.Evidence
	Observation      evidence.Observation
	Report           intelligence.IntelligenceReport
	EvidenceRegistry *evidence.Registry
	Graph            graph.Graph
	Normalized       observations.Collection
}

// RunTLS is a compatibility adapter over the shared investigation engine.
func RunTLS(ctx context.Context, target string, port int, snapshotDir string) (result TLSResult, retErr error) {
	if port == 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		return TLSResult{}, fmt.Errorf("port must be between 1 and 65535")
	}
	unified, registry, err := runUnifiedStage(ctx, target, snapshotDir, investigation.NewTLSStage(target, port))
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
		if len(stage.CollectedEvents) > 0 {
			event := stage.CollectedEvents[0]
			result.Event = &event
		}
		if len(stage.EvidenceRecords) > 0 {
			result.Evidence = stage.EvidenceRecords[0]
		}
		if len(stage.ObservationRecords) > 0 {
			result.Observation = stage.ObservationRecords[0]
		}
	}
	result.Graph = unified.Graph
	result.Report = unified.Report
	result.Normalized = unified.Normalized
	if err != nil {
		return result, err
	}
	if result.Event == nil || strings.TrimSpace(result.Evidence.ID) == "" || strings.TrimSpace(result.Observation.ID) == "" {
		return result, fmt.Errorf("unified TLS stage returned no certificate evidence")
	}
	return result, nil
}
