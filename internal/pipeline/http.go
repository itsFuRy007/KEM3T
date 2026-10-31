package pipeline

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/graph"
	"github.com/itsFuRy007/kem3t/internal/investigation"
	"github.com/itsFuRy007/kem3t/internal/observations"
)

type HTTPResult struct {
	Event            *events.Event
	Evidence         evidence.Evidence
	Observation      evidence.Observation
	EvidenceRegistry *evidence.Registry
	Graph            graph.Graph
	Normalized       observations.Collection
}

// RunHTTP is a compatibility adapter over the shared investigation engine.
func RunHTTP(ctx context.Context, target, scheme string, port int, snapshotDir string) (result HTTPResult, retErr error) {
	if port < 0 || port > 65535 {
		return HTTPResult{}, fmt.Errorf("HTTP port must be between 0 and 65535")
	}
	unified, registry, err := runUnifiedStage(ctx, target, snapshotDir, investigation.NewHTTPStage(target, scheme, port))
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
	result.Normalized = unified.Normalized
	if err != nil {
		return result, err
	}
	if result.Event == nil || strings.TrimSpace(result.Evidence.ID) == "" || strings.TrimSpace(result.Observation.ID) == "" {
		return result, fmt.Errorf("unified HTTP stage returned no response evidence")
	}
	return result, nil
}
