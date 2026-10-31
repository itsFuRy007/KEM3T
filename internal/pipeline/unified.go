package pipeline

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/investigation"
)

// runUnifiedStage is the single execution entry point for the standalone
// TCP/TLS/HTTP compatibility APIs. They retain their result types, but all
// collection, provenance, persistence, graph, intelligence, and history work
// is delegated to the investigation engine.
func runUnifiedStage(ctx context.Context, target, snapshotDir string, stage investigation.Stage) (investigation.Result, *evidence.Registry, error) {
	if ctx == nil {
		return investigation.Result{}, nil, fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return investigation.Result{}, nil, err
	}
	if strings.TrimSpace(snapshotDir) == "" {
		return investigation.Result{}, nil, fmt.Errorf("snapshot directory is required")
	}
	if stage == nil {
		return investigation.Result{}, nil, fmt.Errorf("investigation stage is required")
	}

	registry, err := evidence.OpenRegistry(filepath.Join(snapshotDir, "evidence.db"))
	if err != nil {
		return investigation.Result{}, nil, fmt.Errorf("open shared evidence registry: %w", err)
	}
	result, runErr := (&investigation.Engine{
		Registry: registry,
		Stages: []investigation.Stage{stage},
		SnapshotDir: snapshotDir,
	}).Run(ctx, target)
	if runErr != nil && strings.TrimSpace(result.RunID) == "" {
		if closeErr := registry.Close(); closeErr != nil {
			runErr = errors.Join(runErr, fmt.Errorf("close shared evidence registry: %w", closeErr))
		}
		return result, nil, runErr
	}
	if runErr == nil && result.Partial {
		for _, outcome := range result.Stages {
			if outcome.Error != "" {
				runErr = fmt.Errorf("investigation stage %q failed: %s", outcome.Name, outcome.Error)
				break
			}
		}
		if runErr == nil {
			runErr = errors.New("investigation completed partially")
		}
	}
	return result, registry, runErr
}
