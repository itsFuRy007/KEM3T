package pipeline

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/graph"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/investigation"
	"github.com/itsFuRy007/kem3t/internal/observations"
)

type HTTPResult struct {
	Event            *events.Event
	Evidence         evidence.Evidence
	Observation      evidence.Observation
	Report           intelligence.IntelligenceReport
	EvidenceRegistry *evidence.Registry
	Graph            graph.Graph
	Normalized       observations.Collection
}

// RunHTTP is a compatibility adapter over the shared investigation engine.
func RunHTTP(ctx context.Context, target, scheme string, port int, snapshotDir string) (result HTTPResult, retErr error) {
	if port < 0 || port > 65535 {
		return HTTPResult{}, fmt.Errorf("HTTP port must be between 0 and 65535")
	}
	stageTarget, stageScheme, stagePort, err := normalizeHTTPStageTarget(target, scheme, port)
	if err != nil {
		return HTTPResult{}, err
	}
	unified, registry, err := runUnifiedStage(ctx, stageTarget, snapshotDir, investigation.NewHTTPStage(stageTarget, stageScheme, stagePort))
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
		return result, fmt.Errorf("unified HTTP stage returned no response evidence")
	}
	return result, nil
}

func normalizeHTTPStageTarget(target, scheme string, port int) (string, string, int, error) {
	target = strings.TrimSpace(target)
	parsed, err := url.Parse(target)
	if err == nil && parsed.Host != "" && parsed.Scheme != "" {
		host := parsed.Hostname()
		if host == "" {
			return "", "", 0, fmt.Errorf("HTTP URL must include a hostname")
		}
		if scheme == "" || scheme == "auto" {
			scheme = strings.ToLower(parsed.Scheme)
		}
		if port == 0 && parsed.Port() != "" {
			port, err = strconv.Atoi(parsed.Port())
			if err != nil {
				return "", "", 0, fmt.Errorf("invalid HTTP URL port: %w", err)
			}
		}
		target = host
	}
	if scheme == "" {
		scheme = "auto"
	}
	if port < 0 || port > 65535 {
		return "", "", 0, fmt.Errorf("HTTP port must be between 0 and 65535")
	}
	if net.ParseIP(target) == nil && strings.ContainsAny(target, "/?#") {
		return "", "", 0, fmt.Errorf("HTTP target must be a hostname, IP address, or absolute HTTP URL")
	}
	return target, scheme, port, nil
}
