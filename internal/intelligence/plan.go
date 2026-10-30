package intelligence

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// InvestigationPlan is a deterministic, evidence-linked queue of next actions.
// Rebuilding it against a newer report adapts the queue to newly observed facts.
type InvestigationPlan struct {
	Target   string         `json:"target"`
	Revision string         `json:"revision"`
	Summary  string         `json:"summary"`
	Items    []InvestigationTask `json:"items"`
}

// InvestigationTask is one actionable unit in an investigation plan.
type InvestigationTask struct {
	ID           string   `json:"id"`
	SourceID     string   `json:"source_id"`
	SourceKind   string   `json:"source_kind"`
	Action       string   `json:"action"`
	Rationale    string   `json:"rationale"`
	Priority     int      `json:"priority"`
	PriorityLabel string  `json:"priority_label"`
	Status       string   `json:"status"`
	References   []string `json:"references"`
	OutcomeNote  string   `json:"outcome_note,omitempty"`
	EvidenceIDs  []string `json:"evidence_ids,omitempty"`
}

const (
	TaskRecommended    = "RECOMMENDED"
	TaskCompleted      = "COMPLETED"
	TaskInconclusive   = "INCONCLUSIVE"
	TaskBlocked        = "BLOCKED"
	TaskNotApplicable  = "NOT_APPLICABLE"
	TaskStale          = "NO_LONGER_SUGGESTED"

	FeedbackCompleted     = "COMPLETED"
	FeedbackInconclusive  = "INCONCLUSIVE"
	FeedbackBlocked       = "BLOCKED"
	FeedbackNotApplicable = "NOT_APPLICABLE"
)

// InvestigationFeedback records an investigator's outcome for a prior plan item.
type InvestigationFeedback struct {
	ItemID      string   `json:"item_id"`
	Outcome     string   `json:"outcome"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	Note        string   `json:"note,omitempty"`
}

// BuildAdaptiveInvestigationPlan derives an ordered plan from the current report,
// carries forward prior task outcomes, and applies new investigator feedback.
// It never treats a completed action as proof of the hypothesis being investigated.
func BuildAdaptiveInvestigationPlan(
	report IntelligenceReport,
	previous *InvestigationPlan,
	feedback []InvestigationFeedback,
) (InvestigationPlan, error) {
	target := normalizeFindingTarget(report.Target)
	if target == "" {
		return InvestigationPlan{}, fmt.Errorf("investigation plan target is required")
	}
	if previous != nil {
		if err := previous.Validate(); err != nil { return InvestigationPlan{}, fmt.Errorf("previous plan is invalid: %w", err) }
		if normalizeFindingTarget(previous.Target) != target {
			return InvestigationPlan{}, fmt.Errorf("previous plan target does not match report target")
		}
	}

	candidates := make(map[string]InvestigationTask)
	add := func(sourceID, sourceKind, action, rationale, label string, priority int, refs []string) {
		action = strings.TrimSpace(action)
		if action == "" || strings.TrimSpace(sourceID) == "" {
			return
		}
		refs = stableUnique(append(append([]string(nil), refs...), sourceKind+":"+sourceID))
		id := taskID(sourceKind, sourceID, action)
		candidates[id] = InvestigationTask{
			ID: id, SourceID: sourceID, SourceKind: sourceKind, Action: action,
			Rationale: strings.TrimSpace(rationale), Priority: priority,
			PriorityLabel: label, Status: TaskRecommended, References: refs,
			EvidenceIDs: []string{},
		}
	}

	gapByAction := make(map[string]IntelligenceGap)
	for _, gap := range report.IntelligenceGaps {
		gapByAction[gap.SuggestedAction] = gap
		priority, label := gapPriority(gap.Priority)
		add(gap.ID, "gap", gap.SuggestedAction, gap.WhyItMatters, label, priority, gap.References)
	}

	findingPriority := make(map[string]Priority)
	for _, finding := range report.PrioritizedFindings {
		findingPriority[finding.Finding.Title] = finding.Priority
	}
	for _, step := range report.Narrative.NextSteps {
		if gap, exists := gapByAction[step.Action]; exists {
			_ = gap
			continue
		}
		sourceKind, sourceID := "narrative", step.ID
		if len(step.References) > 0 {
			if kind, id, ok := strings.Cut(step.References[0], ":"); ok && kind != "" && id != "" {
				sourceKind, sourceID = kind, id
			}
		}
		priority, label := 50, "MEDIUM"
		if sourceKind == "finding" {
			if value, exists := findingPriority[sourceID]; exists {
				priority, label = findingPriorityScore(value)
			}
		}
		add(sourceID, sourceKind, step.Action, step.Reason, label, priority, step.References)
	}

	items := make(map[string]InvestigationTask, len(candidates))
	for id, item := range candidates {
		items[id] = item
	}
	if previous != nil {
		for _, old := range previous.Items {
			if current, exists := items[old.ID]; exists {
				current.Status = old.Status
				if current.Status == TaskStale { current.Status = TaskRecommended }
				current.OutcomeNote = old.OutcomeNote
				current.EvidenceIDs = append([]string(nil), old.EvidenceIDs...)
				items[old.ID] = current
				continue
			}
			// Preserve completed work as audit history. Other obsolete tasks remain
			// visible but are explicitly marked as no longer suggested.
			if old.Status != TaskCompleted {
				old.Status = TaskStale
			}
			items[old.ID] = old
		}
	}

	feedbackSeen := make(map[string]struct{}, len(feedback))
	for i, result := range feedback {
		item, exists := items[result.ItemID]
		if !exists {
			return InvestigationPlan{}, fmt.Errorf("feedback %d refers to unknown plan item %q", i, result.ItemID)
		}
		if _, duplicate := feedbackSeen[result.ItemID]; duplicate {
			return InvestigationPlan{}, fmt.Errorf("duplicate feedback for plan item %q", result.ItemID)
		}
		feedbackSeen[result.ItemID] = struct{}{}
		if err := validateFeedback(result); err != nil {
			return InvestigationPlan{}, fmt.Errorf("feedback for plan item %q: %w", result.ItemID, err)
		}
		item.Status = result.Outcome
		item.OutcomeNote = strings.TrimSpace(result.Note)
		item.EvidenceIDs = stableUnique(append([]string(nil), result.EvidenceIDs...))
		items[result.ItemID] = item
	}

	ordered := make([]InvestigationTask, 0, len(items))
	for _, item := range items {
		item.References = stableUnique(append([]string(nil), item.References...))
		item.EvidenceIDs = stableUnique(append([]string(nil), item.EvidenceIDs...))
		ordered = append(ordered, item)
	}
	sort.Slice(ordered, func(i, j int) bool {
		leftActive, rightActive := ordered[i].Status == TaskRecommended || ordered[i].Status == TaskInconclusive,
			ordered[j].Status == TaskRecommended || ordered[j].Status == TaskInconclusive
		if leftActive != rightActive { return leftActive }
		if ordered[i].Priority != ordered[j].Priority { return ordered[i].Priority > ordered[j].Priority }
		return ordered[i].ID < ordered[j].ID
	})

	active, completed, blocked := 0, 0, 0
	for _, item := range ordered {
		switch item.Status {
		case TaskRecommended, TaskInconclusive: active++
		case TaskCompleted: completed++
		case TaskBlocked: blocked++
		}
	}
	plan := InvestigationPlan{
		Target: target, Items: ordered,
		Summary: fmt.Sprintf("%d active actions, %d completed, %d blocked; priorities are qualitative ordering signals, not probabilities.", active, completed, blocked),
	}
	plan.Revision = planRevision(plan)
	if err := plan.Validate(); err != nil {
		return InvestigationPlan{}, fmt.Errorf("validate adaptive investigation plan: %w", err)
	}
	return plan, nil
}

func (p InvestigationPlan) Validate() error {
	if normalizeFindingTarget(p.Target) == "" || strings.TrimSpace(p.Revision) == "" || strings.TrimSpace(p.Summary) == "" {
		return fmt.Errorf("plan target, revision, and summary are required")
	}
	if p.Revision != planRevision(p) {
		return fmt.Errorf("plan revision does not match its contents")
	}
	seen := make(map[string]struct{}, len(p.Items))
	for i, item := range p.Items {
		if strings.TrimSpace(item.ID) == "" || strings.TrimSpace(item.SourceID) == "" || strings.TrimSpace(item.SourceKind) == "" || strings.TrimSpace(item.Action) == "" {
			return fmt.Errorf("plan item %d is incomplete", i)
		}
		if item.Priority < 0 || item.Priority > 100 || item.PriorityLabel == "" {
			return fmt.Errorf("plan item %q has invalid priority", item.ID)
		}
		if item.ID != taskID(item.SourceKind, item.SourceID, item.Action) {
			return fmt.Errorf("plan item %q has an invalid deterministic ID", item.ID)
		}
		switch item.Status {
		case TaskRecommended, TaskCompleted, TaskInconclusive, TaskBlocked, TaskNotApplicable, TaskStale:
		default: return fmt.Errorf("plan item %q has unsupported status %q", item.ID, item.Status)
		}
		if len(item.References) == 0 { return fmt.Errorf("plan item %q has no evidence references", item.ID) }
		for _, ref := range item.References {
			if strings.TrimSpace(ref) == "" { return fmt.Errorf("plan item %q has an empty reference", item.ID) }
		}
		for _, evidenceID := range item.EvidenceIDs {
			if strings.TrimSpace(evidenceID) == "" { return fmt.Errorf("plan item %q has an empty evidence ID", item.ID) }
		}
		if _, exists := seen[item.ID]; exists { return fmt.Errorf("duplicate plan item ID %q", item.ID) }
		seen[item.ID] = struct{}{}
	}
	return nil
}

func validateFeedback(feedback InvestigationFeedback) error {
	switch feedback.Outcome {
	case FeedbackCompleted:
		if len(feedback.EvidenceIDs) == 0 { return fmt.Errorf("completed feedback requires evidence IDs") }
	case FeedbackInconclusive, FeedbackBlocked, FeedbackNotApplicable:
		if strings.TrimSpace(feedback.Note) == "" { return fmt.Errorf("%s feedback requires an explanatory note", feedback.Outcome) }
	default:
		return fmt.Errorf("unsupported outcome %q", feedback.Outcome)
	}
	for _, id := range feedback.EvidenceIDs {
		if strings.TrimSpace(id) == "" { return fmt.Errorf("feedback contains an empty evidence ID") }
	}
	return nil
}

func gapPriority(priority string) (int, string) {
	switch priority {
	case "HIGH": return 90, "HIGH"
	case "MEDIUM": return 65, "MEDIUM"
	default: return 40, "LOW"
	}
}

func findingPriorityScore(priority Priority) (int, string) {
	switch priority {
	case PriorityHigh: return 85, "HIGH"
	case PriorityInterest: return 65, "MEDIUM"
	case PriorityInfo: return 40, "LOW"
	default: return 25, "LOW"
	}
}

func taskID(kind, sourceID, action string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + sourceID + "\x00" + action))
	return "task:" + hex.EncodeToString(sum[:8])
}

func planRevision(plan InvestigationPlan) string {
	parts := []string{plan.Target}
	for _, item := range plan.Items {
		parts = append(parts, strings.Join([]string{item.ID, item.Status, item.Action, item.Rationale, fmt.Sprint(item.Priority), item.PriorityLabel, item.OutcomeNote, strings.Join(item.References, ","), strings.Join(item.EvidenceIDs, ",")}, "|"))
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:12])
}

 
// InvestigationPlanState persists the previous plan and feedback between runs.
type InvestigationPlanState struct {
	PreviousPlan *InvestigationPlan       `json:"previous_plan,omitempty"`
	Feedback     []InvestigationFeedback `json:"feedback"`
}

// Validate ensures queued feedback can be applied to the saved plan without
// guessing task identities or accepting incomplete investigator outcomes.
func (s InvestigationPlanState) Validate() error {
	if s.PreviousPlan == nil {
		if len(s.Feedback) != 0 {
			return fmt.Errorf("feedback cannot be queued without a previous investigation plan")
		}
		return nil
	}
	if err := s.PreviousPlan.Validate(); err != nil {
		return fmt.Errorf("previous investigation plan: %w", err)
	}
	known := make(map[string]struct{}, len(s.PreviousPlan.Items))
	for _, item := range s.PreviousPlan.Items {
		known[item.ID] = struct{}{}
	}
	seen := make(map[string]struct{}, len(s.Feedback))
	for i, feedback := range s.Feedback {
		if _, ok := known[feedback.ItemID]; !ok {
			return fmt.Errorf("feedback %d refers to unknown plan item %q", i, feedback.ItemID)
		}
		if _, duplicate := seen[feedback.ItemID]; duplicate {
			return fmt.Errorf("duplicate feedback for plan item %q", feedback.ItemID)
		}
		seen[feedback.ItemID] = struct{}{}
		if err := validateFeedback(feedback); err != nil {
			return fmt.Errorf("feedback for plan item %q: %w", feedback.ItemID, err)
		}
	}
	return nil
}
