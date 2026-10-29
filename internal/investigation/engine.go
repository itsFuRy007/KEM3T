package investigation

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/graph"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
)

// Stage is one bounded investigation capability. Implementations must register
// normalized evidence and observations in the supplied shared registry.
// A stage must not close the registry or widen the caller's authorized scope.
type Stage interface {
	Name() string
	Run(context.Context, string, *evidence.Registry) (StageResult, error)
}

// StageResult describes what a stage contributed without duplicating its data.
type StageResult struct {
	Events       int      `json:"events"`
	Evidence     int      `json:"evidence"`
	Observations int      `json:"observations"`
	Limitations  []string `json:"limitations,omitempty"`
}

// StageOutcome preserves partial success and makes failures visible in reports.
type StageOutcome struct {
	Name   string      `json:"name"`
	Result StageResult `json:"result"`
	Error  string      `json:"error,omitempty"`
}

// Result is a coherent view assembled from one registry after all stages finish.
type Result struct {
	Target  string                       `json:"target"`
	RunID   string                       `json:"run_id"`
	Stages  []StageOutcome               `json:"stages"`
	Graph   graph.Graph                  `json:"graph"`
	Report  intelligence.IntelligenceReport `json:"report"`
	Partial bool                         `json:"partial"`
}

// Engine coordinates stages against one evidence registry. It deliberately
// does not decide which active network actions are authorized: callers provide
// only stages configured for their explicit scope and policy.
type Engine struct {
	Registry *evidence.Registry
	Stages   []Stage
	Now      func() time.Time
}

func (e *Engine) Run(ctx context.Context, target string) (result Result, retErr error) {
	if ctx == nil {
		return Result{}, errors.New("context is required")
	}
	if err := ctx.Err(); err != nil {
		return Result{}, err
	}
	target = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	if target == "" {
		return Result{}, errors.New("target is required")
	}
	if e.Registry == nil {
		return Result{}, errors.New("shared evidence registry is required")
	}
	if len(e.Stages) == 0 {
		return Result{}, errors.New("at least one investigation stage is required")
	}
	now := e.Now
	if now == nil {
		now = time.Now
	}
	seen := make(map[string]struct{}, len(e.Stages))
	for _, stage := range e.Stages {
		if stage == nil || strings.TrimSpace(stage.Name()) == "" {
			return Result{}, errors.New("investigation stages must be non-nil and named")
		}
		name := strings.TrimSpace(stage.Name())
		if _, exists := seen[name]; exists {
			return Result{}, fmt.Errorf("duplicate investigation stage %q", name)
		}
		seen[name] = struct{}{}
	}
	started := now().UTC()
	evidenceBefore := make(map[string]struct{})
	for _, item := range e.Registry.AllEvidence() { evidenceBefore[item.ID] = struct{}{} }
	run := evidence.CollectionRun{
		ID: fmt.Sprintf("investigation-%d", started.UnixNano()),
		Target: target, StartedAt: started, Status: evidence.CollectionRunRunning,
	}
	if err := e.Registry.AddCollectionRun(run); err != nil {
		return Result{}, fmt.Errorf("start investigation run: %w", err)
	}
	result = Result{Target: target, RunID: run.ID, Stages: make([]StageOutcome, 0, len(e.Stages))}
	for _, stage := range e.Stages {
		if err := ctx.Err(); err != nil {
			retErr = err
			break
		}
		name := strings.TrimSpace(stage.Name())
		stageResult, err := stage.Run(ctx, target, e.Registry)
		outcome := StageOutcome{Name: name, Result: stageResult}
		if err != nil {
			outcome.Error = err.Error()
			result.Partial = true
		}
		result.Stages = append(result.Stages, outcome)
	}
	if ctx.Err() != nil && retErr == nil {
		retErr = ctx.Err()
	}
	// A failed source does not discard useful evidence from successful stages.
	if len(e.Registry.AllEvidence()) > 0 {
		built, err := graph.BuildFromRegistry(e.Registry)
		if err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("build investigation graph: %w", err))
		} else {
			result.Graph = built
		}
		report, err := (&intelligence.ReportEngine{}).Build(target, nil, e.Registry)
		if err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("build intelligence report: %w", err))
		} else {
			result.Report = report
		}
	} else if retErr == nil {
		retErr = errors.New("investigation completed without registering evidence")
	}
	run.FinishedAt = now().UTC()
	run.EventCount = 0
	run.AddressCount = 0
	for _, outcome := range result.Stages {
		run.EventCount += outcome.Result.Events
		if outcome.Error != "" {
			run.ErrorMessage = strings.TrimSpace(run.ErrorMessage + "; " + outcome.Name + ": " + outcome.Error)
		}
	}
	newEvidence := 0
	for _, item := range e.Registry.AllEvidence() {
		if _, existed := evidenceBefore[item.ID]; existed { continue }
		newEvidence++
		if item.Type == evidence.TypeDNSAddress { run.AddressCount++ }
	}
	if result.Partial || retErr != nil {
		run.Status = evidence.CollectionRunFailed
	} else if newEvidence == 0 {
		run.Status = evidence.CollectionRunFailed
		if run.ErrorMessage == "" { run.ErrorMessage = "investigation produced no new evidence" }
	} else {
		run.Status = evidence.CollectionRunCompleted
	}
	if err := e.Registry.UpdateCollectionRun(run); err != nil {
		retErr = errors.Join(retErr, fmt.Errorf("finalize investigation run: %w", err))
	}
	return result, retErr
}
