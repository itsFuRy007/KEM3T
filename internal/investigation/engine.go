package investigation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/graph"
	"github.com/itsFuRy007/kem3t/internal/history"
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

// PlanningState is a read-only snapshot supplied after each completed stage.
type PlanningState struct {
	Target       string
	Evidence     []evidence.Evidence
	NewEvidence  []evidence.Evidence
	Observations []evidence.Observation
	Completed    []StageOutcome
	Scheduled    []string
}

// Planner schedules additional bounded stages from newly collected evidence.
// Returned stages must still respect the caller's explicit authorization scope.
type Planner interface {
	Next(context.Context, PlanningState) ([]Stage, error)
}

// Engine coordinates stages against one shared evidence registry. It deliberately
// does not decide which active network actions are authorized: callers provide
// only stages configured for their explicit scope and policy.
type Engine struct {
	Registry  *evidence.Registry
	Stages    []Stage
	Planner   Planner
	MaxStages  int
	SnapshotDir string
	Now        func() time.Time
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
	if net.ParseIP(target) == nil && !evidence.IsValidDomain(target) {
		return Result{}, fmt.Errorf("target must be a valid hostname or IP address")
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
	maxStages := e.MaxStages
	if maxStages <= 0 { maxStages = 16 }
	if len(e.Stages) > maxStages { return Result{}, fmt.Errorf("initial stage count %d exceeds maximum %d", len(e.Stages), maxStages) }
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
	queue := append([]Stage(nil), e.Stages...)
	for index := 0; index < len(queue); index++ {
		stage := queue[index]
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
		if e.Planner != nil && ctx.Err() == nil {
			allEvidence := e.Registry.AllEvidence()
			newEvidence := make([]evidence.Evidence, 0, len(allEvidence))
			for _, item := range allEvidence { if _, existed := evidenceBefore[item.ID]; !existed { newEvidence = append(newEvidence, item) } }
			scheduled := make([]string, 0, len(queue)-index-1)
			for _, pending := range queue[index+1:] { scheduled = append(scheduled, strings.TrimSpace(pending.Name())) }
			next, planErr := e.Planner.Next(ctx, PlanningState{
				Target: target, Evidence: allEvidence, NewEvidence: newEvidence,
				Observations: e.Registry.AllObservations(),
				Completed: append([]StageOutcome(nil), result.Stages...), Scheduled: scheduled,
			})
			if planErr != nil {
				retErr = fmt.Errorf("plan next investigation stages: %w", planErr)
				result.Partial = true
				break
			}
			for _, candidate := range next {
				if candidate == nil || strings.TrimSpace(candidate.Name()) == "" {
					retErr = errors.New("planner returned a nil or unnamed stage")
					result.Partial = true
					break
				}
				name := strings.TrimSpace(candidate.Name())
				if _, exists := seen[name]; exists {
					retErr = fmt.Errorf("planner returned duplicate investigation stage %q", name)
					result.Partial = true
					break
				}
				seen[name] = struct{}{}
				queue = append(queue, candidate)
				if len(queue) > maxStages {
					retErr = fmt.Errorf("adaptive investigation exceeded maximum of %d stages", maxStages)
					result.Partial = true
					break
				}
			}
			if retErr != nil { break }
		}
	}
	if ctx.Err() != nil && retErr == nil {
		retErr = ctx.Err()
	}
	// A failed source does not discard useful evidence from successful stages.
	// Keep the returned graph scoped to this investigation, including IPs
	// explicitly linked by in-scope DNS evidence from the same registry.
	scopedEvidence, scopedObservations := scopedRegistryRecords(target, e.Registry)
	built, err := graph.Build(scopedEvidence, scopedObservations)
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
	run.FinishedAt = now().UTC()
	run.EventCount = 0
	run.AddressCount = 0
	for _, outcome := range result.Stages {
		run.EventCount += outcome.Result.Events
		if outcome.Error != "" {
			message := outcome.Name + ": " + outcome.Error
			if run.ErrorMessage == "" { run.ErrorMessage = message } else { run.ErrorMessage += "; " + message }
		}
	}
	for _, item := range e.Registry.AllEvidence() {
		if _, existed := evidenceBefore[item.ID]; existed { continue }
		if item.Type == evidence.TypeDNSAddress { run.AddressCount++ }
	}
	if retErr != nil && run.ErrorMessage == "" { run.ErrorMessage = retErr.Error() }
	if result.Partial || retErr != nil {
		run.Status = evidence.CollectionRunFailed
	} else {
		run.Status = evidence.CollectionRunCompleted
	}
	if err := e.Registry.UpdateCollectionRun(run); err != nil {
		retErr = errors.Join(retErr, fmt.Errorf("finalize investigation run: %w", err))
	}
	if run.Status == evidence.CollectionRunCompleted && strings.TrimSpace(e.SnapshotDir) != "" {
		if err := history.PersistRunSnapshot(e.SnapshotDir, run, e.Registry); err != nil {
			retErr = errors.Join(retErr, fmt.Errorf("persist unified investigation history: %w", err))
		}
	}
	return result, retErr
}


// scopedRegistryRecords limits graph construction to the requested target,
// its subdomains, and IPs directly observed in DNS evidence for that scope.
func scopedRegistryRecords(target string, registry *evidence.Registry) ([]evidence.Evidence, []evidence.Observation) {
	all := registry.AllEvidence()
	entities := map[string]struct{}{target: {}}
	for _, item := range all {
		entity := normalizeEntity(item.EntityID)
		if withinDomainScope(entity, target) && item.Type == evidence.TypeDNSAddress {
			entities[normalizeEntity(item.Value)] = struct{}{}
		}
	}
	selected := make([]evidence.Evidence, 0, len(all))
	selectedIDs := make(map[string]struct{})
	for _, item := range all {
		if _, ok := entities[normalizeEntity(item.EntityID)]; !ok && !withinDomainScope(normalizeEntity(item.EntityID), target) { continue }
		selected = append(selected, item)
		selectedIDs[item.ID] = struct{}{}
	}
	observations := registry.AllObservations()
	selectedObservations := make([]evidence.Observation, 0, len(observations))
	for _, observation := range observations {
		if _, ok := selectedIDs[observation.EvidenceID]; ok { selectedObservations = append(selectedObservations, observation) }
	}
	return selected, selectedObservations
}

func normalizeEntity(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func withinDomainScope(entity, target string) bool {
	if entity == target { return true }
	if net.ParseIP(target) != nil { return false }
	return strings.HasSuffix(entity, "."+target)
}
