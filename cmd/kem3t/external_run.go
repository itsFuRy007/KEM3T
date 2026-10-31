package main

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/history"
	"github.com/itsFuRy007/kem3t/internal/investigation"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
)

type externalCollectionFunc func(context.Context, *evidence.Registry, string) error

type externalCollectionStage struct {
	stageName string
	timeout   time.Duration
	collect   externalCollectionFunc
	failure   *error
}

func (s externalCollectionStage) Name() string { return strings.TrimSpace(s.stageName) }

func (s externalCollectionStage) Run(ctx context.Context, target string, registry *evidence.Registry) (investigation.StageResult, error) {
	if ctx == nil {
		return investigation.StageResult{}, fmt.Errorf("context is required")
	}
	if registry == nil {
		return investigation.StageResult{}, fmt.Errorf("shared evidence registry is required")
	}
	if s.collect == nil {
		return investigation.StageResult{}, fmt.Errorf("external collection function is required")
	}
	lookupCtx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	beforeEvidence := make(map[string]struct{})
	for _, item := range registry.AllEvidence() {
		beforeEvidence[item.ID] = struct{}{}
	}
	beforeObservations := make(map[string]struct{})
	for _, item := range registry.AllObservations() {
		beforeObservations[item.ID] = struct{}{}
	}

	if err := s.collect(lookupCtx, registry, target); err != nil {
		wrapped := fmt.Errorf("%s collection: %w", s.Name(), err)
		if s.failure != nil {
			*s.failure = wrapped
		}
		return investigation.StageResult{}, wrapped
	}
	stageResult := investigation.StageResult{}
	for _, item := range registry.AllEvidence() {
		if _, existed := beforeEvidence[item.ID]; !existed {
			stageResult.EvidenceRecords = append(stageResult.EvidenceRecords, item)
		}
	}
	for _, item := range registry.AllObservations() {
		if _, existed := beforeObservations[item.ID]; !existed {
			stageResult.ObservationRecords = append(stageResult.ObservationRecords, item)
		}
	}
	stageResult.Events = len(stageResult.ObservationRecords)
	stageResult.Evidence = len(stageResult.EvidenceRecords)
	stageResult.Observations = len(stageResult.ObservationRecords)
	return stageResult, nil
}

// runExternalCollection delegates external-source lifecycle, provenance,
// persistence, graph/report construction, and history to the same engine used
// by DNS/TCP/TLS/HTTP investigations.
func runExternalCollection(target, snapshotDir, runPrefix string, timeout time.Duration, collect externalCollectionFunc) (retErr error) {
	target = history.NormalizeTarget(target)
	snapshotDir = strings.TrimSpace(snapshotDir)
	runPrefix = strings.ToLower(strings.TrimSpace(runPrefix))
	if target == "" {
		return fmt.Errorf("target is required")
	}
	if snapshotDir == "" {
		return fmt.Errorf("snapshot directory is required")
	}
	if runPrefix == "" {
		return fmt.Errorf("collection stage name is required")
	}
	if timeout <= 0 {
		return fmt.Errorf("collection timeout must be positive")
	}
	if collect == nil {
		return fmt.Errorf("external collection function is required")
	}

	registry, err := evidence.OpenRegistry(filepath.Join(snapshotDir, "evidence.db"))
	if err != nil {
		return fmt.Errorf("open shared evidence registry: %w", err)
	}
	defer func() {
		if closeErr := registry.Close(); closeErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("close shared evidence registry: %w", closeErr))
		}
	}()

	var stageFailure error
	stage := &externalCollectionStage{stageName: runPrefix, timeout: timeout, collect: collect, failure: &stageFailure}
	result, runErr := (&investigation.Engine{
		Registry:    registry,
		Stages:      []investigation.Stage{stage},
		SnapshotDir: snapshotDir,
	}).Run(context.Background(), target)
	if stageFailure != nil {
		return fmt.Errorf("external investigation: %w", stageFailure)
	}
	if runErr != nil {
		return fmt.Errorf("external investigation: %w", runErr)
	}
	if result.Partial {
		for _, stage := range result.Stages {
			if stage.Error != "" {
				return fmt.Errorf("external investigation stage %q failed: %s", stage.Name, stage.Error)
			}
		}
		return fmt.Errorf("external investigation completed partially")
	}
	printExternalIntelligence(result.Report)
	return nil
}

func printExternalIntelligence(report intelligence.IntelligenceReport) {
	fmt.Println("\n[KEM3T INTELLIGENCE]")
	safePrintf("Correlations: %d | Discoveries: %d | Hypotheses: %d | Verification assessments: %d | Intelligence gaps: %d\n",
		len(report.Correlations), len(report.Discoveries), len(report.Hypotheses),
		len(report.VerificationAssessments), len(report.IntelligenceGaps))
	for _, hypothesis := range report.Hypotheses {
		safePrintf("[HYPOTHESIS | %s] %s\n", hypothesis.Confidence, hypothesis.Title)
		safePrintf("  %s\n", hypothesis.Statement)
		if hypothesis.Alternative != "" {
			safePrintf("  Alternative: %s\n", hypothesis.Alternative)
		}
		if hypothesis.Limitations != "" {
			safePrintf("  Limitation: %s\n", hypothesis.Limitations)
		}
	}
}
