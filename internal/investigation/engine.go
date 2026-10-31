package investigation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/graph"
	"github.com/itsFuRy007/kem3t/internal/history"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
	"github.com/itsFuRy007/kem3t/internal/observations"
)

type Stage interface {
	Name() string
	Run(context.Context, string, *evidence.Registry) (StageResult, error)
}

type StageResult struct {
	Events       int                    `json:"events"`
	Evidence     int                    `json:"evidence"`
	Observations int                    `json:"observations"`
	Findings            []intelligence.Finding `json:"findings,omitempty"`
	Limitations         []string               `json:"limitations,omitempty"`
	CollectedEvents     []events.Event         `json:"collected_events,omitempty"`
	EvidenceRecords     []evidence.Evidence    `json:"evidence_records,omitempty"`
	ObservationRecords  []evidence.Observation `json:"observation_records,omitempty"`
}

type StageOutcome struct {
	Name   string      `json:"name"`
	Result StageResult `json:"result"`
	Error  string      `json:"error,omitempty"`
}

type Result struct {
	Target           string                          `json:"target"`
	RunID            string                          `json:"run_id"`
	Stages           []StageOutcome                  `json:"stages"`
	Graph            graph.Graph                     `json:"graph"`
	Normalized       observations.Collection         `json:"normalized"`
	Report           intelligence.IntelligenceReport `json:"report"`
	Partial          bool                            `json:"partial"`
	HistoryPersisted bool                            `json:"history_persisted"`
}

type PlanningState struct {
	Target       string
	Evidence     []evidence.Evidence
	NewEvidence  []evidence.Evidence
	Observations []evidence.Observation
	Findings     []intelligence.Finding
	Completed    []StageOutcome
	Scheduled    []string
	// Limitations lets planners report decisions even when they cannot enqueue
	// a stage (for example, when an expansion cap has no remaining capacity).
	Limitations *[]string
}

type Planner interface {
	Next(context.Context, PlanningState) ([]Stage, error)
}

type Engine struct {
	Registry    *evidence.Registry
	Stages      []Stage
	Planner     Planner
	MaxStages   int
	SnapshotDir string
	Now         func() time.Time
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
	if maxStages <= 0 {
		maxStages = 16
	}
	if len(e.Stages) > maxStages {
		return Result{}, fmt.Errorf("initial stage count %d exceeds maximum %d", len(e.Stages), maxStages)
	}
	started := now().UTC()
	evidenceBefore := make(map[string]struct{})
	for _, item := range e.Registry.AllEvidence() {
		evidenceBefore[item.ID] = struct{}{}
	}
	run := evidence.CollectionRun{ID: fmt.Sprintf("investigation-%d", started.UnixNano()), Target: target, StartedAt: started, Status: evidence.CollectionRunRunning}
	if err := e.Registry.AddCollectionRun(run); err != nil {
		return Result{}, fmt.Errorf("start investigation run: %w", err)
	}
	result = Result{Target: target, RunID: run.ID, Stages: make([]StageOutcome, 0, len(e.Stages))}
	queue := append([]Stage(nil), e.Stages...)
	plannerLimitations := make([]string, 0)

	for index := 0; index < len(queue); index++ {
		stage := queue[index]
		if err := ctx.Err(); err != nil {
			retErr = err
			break
		}
		name := strings.TrimSpace(stage.Name())
		stageCtx := evidence.WithObservationProvenance(ctx, run.ID, name)
		stageResult, err := stage.Run(stageCtx, target, e.Registry)
		outcome := StageOutcome{Name: name, Result: stageResult}
		if err != nil {
			outcome.Error = err.Error()
			result.Partial = true
		}
		result.Stages = append(result.Stages, outcome)

		if e.Planner != nil && ctx.Err() == nil {
			allEvidence := e.Registry.AllEvidence()
			newEvidence := make([]evidence.Evidence, 0, len(allEvidence))
			for _, item := range allEvidence {
				if _, existed := evidenceBefore[item.ID]; !existed {
					newEvidence = append(newEvidence, item)
				}
			}
			findings := collectFindings(result.Stages)
			scheduled := make([]string, 0, len(queue)-index-1)
			for _, pending := range queue[index+1:] {
				scheduled = append(scheduled, strings.TrimSpace(pending.Name()))
			}
			next, planErr := e.Planner.Next(ctx, PlanningState{
				Target: target, Evidence: allEvidence, NewEvidence: newEvidence,
				Observations: e.Registry.AllObservations(), Findings: findings,
				Completed: append([]StageOutcome(nil), result.Stages...), Scheduled: scheduled,
				Limitations: &plannerLimitations,
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
				candidateName := strings.TrimSpace(candidate.Name())
				if _, exists := seen[candidateName]; exists {
					retErr = fmt.Errorf("planner returned duplicate investigation stage %q", candidateName)
					result.Partial = true
					break
				}
				seen[candidateName] = struct{}{}
				queue = append(queue, candidate)
				if len(queue) > maxStages {
					retErr = fmt.Errorf("adaptive investigation exceeded maximum of %d stages", maxStages)
					result.Partial = true
					break
				}
			}
			if retErr != nil {
				break
			}
		}
	}
	if ctx.Err() != nil && retErr == nil {
		retErr = ctx.Err()
	}

	collectedEvents := make([]events.Event, 0)
	for _, outcome := range result.Stages {
		collectedEvents = append(collectedEvents, outcome.Result.CollectedEvents...)
	}
	result.Normalized = observations.NormalizeEvents(collectedEvents)
	if len(result.Normalized.Rejected) > 0 {
		result.Partial = true
		retErr = errors.Join(retErr, fmt.Errorf("normalize investigation events: %s", result.Normalized.Rejected[0].Reason))
	}

	scopedEvidence, scopedObservations := scopedRegistryRecords(target, e.Registry)
	observations.AttachEvidence(&result.Normalized, scopedObservations)
	built, err := graph.Build(scopedEvidence, scopedObservations)
	if err == nil && len(result.Normalized.Services) > 0 {
		built, err = graph.AttachServices(built, result.Normalized.Services)
	}
	if err != nil {
		retErr = errors.Join(retErr, fmt.Errorf("build unified investigation graph: %w", err))
		result.Partial = true
	} else {
		result.Graph = built
	}

	findings := collectFindings(result.Stages)
	report, err := (&intelligence.ReportEngine{}).Build(target, findings, e.Registry)
	if err != nil {
		retErr = errors.Join(retErr, fmt.Errorf("build intelligence report: %w", err))
	} else {
		result.Report = report
		for _, limitation := range plannerLimitations {
			result.Report.Narrative.Limitations = appendUniqueLimitation(
				result.Report.Narrative.Limitations,
				"planner: "+limitation,
			)
		}
		for _, outcome := range result.Stages {
			for _, limitation := range outcome.Result.Limitations {
				result.Report.Narrative.Limitations = appendUniqueLimitation(
					result.Report.Narrative.Limitations,
					outcome.Name+": "+limitation,
				)
			}
			if outcome.Error != "" {
				result.Report.Narrative.Limitations = appendUniqueLimitation(
					result.Report.Narrative.Limitations,
					outcome.Name+" failed: "+outcome.Error,
				)
			}
		}
	}

	run.FinishedAt = now().UTC()
	for _, outcome := range result.Stages {
		run.EventCount += outcome.Result.Events
		if outcome.Error != "" {
			message := outcome.Name + ": " + outcome.Error
			if run.ErrorMessage == "" {
				run.ErrorMessage = message
			} else {
				run.ErrorMessage += "; " + message
			}
		}
	}
	addressSet := make(map[string]struct{})
	for _, outcome := range result.Stages {
		for _, item := range outcome.Result.EvidenceRecords {
			if item.Type == evidence.TypeDNSAddress {
				addressSet[item.Value] = struct{}{}
			}
		}
	}
	run.AddressCount = len(addressSet)
	if retErr != nil && run.ErrorMessage == "" {
		run.ErrorMessage = retErr.Error()
	}
	if result.Partial || retErr != nil {
		run.Status = evidence.CollectionRunFailed
	} else {
		run.Status = evidence.CollectionRunCompleted
	}
	if retErr != nil {
		result.Partial = true
	}
	if err := e.Registry.UpdateCollectionRun(run); err != nil {
		finalizeErr := fmt.Errorf("finalize investigation run: %w", err)
		retErr = errors.Join(retErr, finalizeErr)
		result.Partial = true
		run.Status = evidence.CollectionRunFailed
		if run.ErrorMessage == "" {
			run.ErrorMessage = finalizeErr.Error()
		} else {
			run.ErrorMessage += "; " + finalizeErr.Error()
		}
		if retryErr := e.Registry.UpdateCollectionRun(run); retryErr != nil {
			retErr = errors.Join(retErr, fmt.Errorf("mark investigation run failed after finalization error: %w", retryErr))
		}
		if result.Report.Target != "" && retErr != nil {
			result.Report.Narrative.Limitations = appendUniqueLimitation(
				result.Report.Narrative.Limitations,
				"Investigation finalization: "+retErr.Error(),
			)
		}
		return result, retErr
	}
	if run.Status == evidence.CollectionRunCompleted && strings.TrimSpace(e.SnapshotDir) != "" {
		if err := history.PersistRunSnapshot(e.SnapshotDir, run, e.Registry); err != nil {
			persistErr := fmt.Errorf("persist unified investigation history: %w", err)
			retErr = errors.Join(retErr, persistErr)
			result.Partial = true
			run.Status = evidence.CollectionRunFailed
			if run.ErrorMessage == "" {
				run.ErrorMessage = persistErr.Error()
			} else {
				run.ErrorMessage += "; " + persistErr.Error()
			}
			if updateErr := e.Registry.UpdateCollectionRun(run); updateErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("mark investigation run failed after history persistence error: %w", updateErr))
			}
		} else {
			result.HistoryPersisted = true
		}
	}
	if result.Report.Target != "" && retErr != nil {
		result.Report.Narrative.Limitations = appendUniqueLimitation(
			result.Report.Narrative.Limitations,
			"Investigation incomplete: "+retErr.Error(),
		)
	}
	return result, retErr
}

func appendUniqueLimitation(existing []string, value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return existing
	}
	for _, current := range existing {
		if current == value {
			return existing
		}
	}
	return append(existing, value)
}

func collectFindings(stages []StageOutcome) []intelligence.Finding {
	var findings []intelligence.Finding
	for _, stage := range stages {
		findings = append(findings, stage.Result.Findings...)
	}
	return findings
}

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
		if _, ok := entities[normalizeEntity(item.EntityID)]; !ok && !withinDomainScope(normalizeEntity(item.EntityID), target) {
			continue
		}
		selected = append(selected, item)
		selectedIDs[item.ID] = struct{}{}
	}
	observations := registry.AllObservations()
	selectedObservations := make([]evidence.Observation, 0, len(observations))
	for _, observation := range observations {
		if _, ok := selectedIDs[observation.EvidenceID]; ok {
			selectedObservations = append(selectedObservations, observation)
		}
	}
	return selected, selectedObservations
}

func normalizeEntity(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}

func withinDomainScope(entity, target string) bool {
	if entity == target {
		return true
	}
	if net.ParseIP(target) != nil {
		return false
	}
	return strings.HasSuffix(entity, "."+target)
}
