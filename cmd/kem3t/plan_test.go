package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/itsFuRy007/kem3t/internal/intelligence"
)

func TestRunRejectsPlanStateOutsideDNSMode(t *testing.T) {
	oldArgs := os.Args
	os.Args = []string{"kem3t", "-mode", "tls", "-target", "example.com", "-plan-state", "plan.json"}
	defer func() { os.Args = oldArgs }()
	err := run()
	if err == nil || !strings.Contains(err.Error(), "-plan-state is supported only in DNS mode") {
		t.Fatalf("run() error = %v, want DNS-only plan-state error", err)
	}
}

func TestWriteJSONAtomicUsesPrivatePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state", "plan.json")
	if err := writeJSONAtomic(path, []byte("{\"ok\":true}")); err != nil {
		t.Fatalf("writeJSONAtomic() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	if string(data) != "{\"ok\":true}\n" { t.Fatalf("unexpected output: %q", data) }
	info, err := os.Stat(path)
	if err != nil { t.Fatal(err) }
	if info.Mode().Perm() != 0600 { t.Fatalf("permissions = %04o, want 0600", info.Mode().Perm()) }
}

func writeTestPlanState(t *testing.T) (string, intelligence.InvestigationPlan) {
	t.Helper()
	report := intelligence.IntelligenceReport{
		Target: "example.com",
		Narrative: intelligence.ResearchNarrative{NextSteps: []intelligence.NarrativeNextStep{{
			ID: "next-step:inspect", Action: "Inspect the independent source.", Reason: "Verify the relationship.",
			References: []string{"finding:service"},
		}}},
	}
	plan, err := intelligence.BuildAdaptiveInvestigationPlan(report, nil, nil)
	if err != nil { t.Fatal(err) }
	state := intelligence.InvestigationPlanState{PreviousPlan: &plan, Feedback: []intelligence.InvestigationFeedback{}}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil { t.Fatal(err) }
	path := filepath.Join(t.TempDir(), "plan-state.json")
	if err := os.WriteFile(path, data, 0600); err != nil { t.Fatal(err) }
	return path, plan
}

func TestRunPlanFeedbackQueuesAndPersistsValidatedFeedback(t *testing.T) {
	path, plan := writeTestPlanState(t)
	oldArgs := os.Args
	os.Args = []string{"kem3t", "-mode", "plan-feedback", "-plan-state", path,
		"-plan-feedback-item", plan.Items[0].ID,
		"-plan-feedback-outcome", "COMPLETED",
		"-plan-feedback-evidence-ids", "evidence:one, evidence:two"}
	defer func() { os.Args = oldArgs }()
	if err := run(); err != nil { t.Fatalf("run() error = %v", err) }
	data, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	var state intelligence.InvestigationPlanState
	if err := json.Unmarshal(data, &state); err != nil { t.Fatal(err) }
	if err := state.Validate(); err != nil { t.Fatalf("persisted state is invalid: %v", err) }
	if len(state.Feedback) != 1 || state.Feedback[0].Outcome != intelligence.FeedbackCompleted {
		t.Fatalf("feedback was not persisted: %#v", state.Feedback)
	}
	if len(state.Feedback[0].EvidenceIDs) != 2 { t.Fatalf("evidence IDs = %#v, want two IDs", state.Feedback[0].EvidenceIDs) }
}

func TestRunPlanFeedbackRejectsInvalidFeedbackWithoutChangingState(t *testing.T) {
	path, plan := writeTestPlanState(t)
	before, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	oldArgs := os.Args
	os.Args = []string{"kem3t", "-mode", "plan-feedback", "-plan-state", path,
		"-plan-feedback-item", plan.Items[0].ID, "-plan-feedback-outcome", "COMPLETED"}
	defer func() { os.Args = oldArgs }()
	if err := run(); err == nil { t.Fatal("expected completed feedback without evidence to fail") }
	after, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	if string(after) != string(before) { t.Fatal("invalid feedback modified the saved plan state") }
}

func TestRunPlanFeedbackRejectsDuplicateQueuedTask(t *testing.T) {
	path, plan := writeTestPlanState(t)
	stateData, err := os.ReadFile(path)
	if err != nil { t.Fatal(err) }
	var state intelligence.InvestigationPlanState
	if err := json.Unmarshal(stateData, &state); err != nil { t.Fatal(err) }
	state.Feedback = []intelligence.InvestigationFeedback{{ItemID: plan.Items[0].ID, Outcome: intelligence.FeedbackBlocked, Note: "Waiting for authorization."}}
	stateData, err = json.Marshal(state)
	if err != nil { t.Fatal(err) }
	if err := os.WriteFile(path, stateData, 0600); err != nil { t.Fatal(err) }
	oldArgs := os.Args
	os.Args = []string{"kem3t", "-mode", "plan-feedback", "-plan-state", path,
		"-plan-feedback-item", plan.Items[0].ID, "-plan-feedback-outcome", "BLOCKED", "-plan-feedback-note", "Still waiting."}
	defer func() { os.Args = oldArgs }()
	if err := run(); err == nil { t.Fatal("expected duplicate queued feedback to fail") }
}

func TestInvestigationPlanStateJSONRoundTrip(t *testing.T) {
	state := intelligence.InvestigationPlanState{Feedback: []intelligence.InvestigationFeedback{{
		ItemID: "task:123", Outcome: intelligence.FeedbackBlocked, Note: "Need access approval.",
	}}}
	data, err := json.Marshal(state)
	if err != nil { t.Fatal(err) }
	var decoded intelligence.InvestigationPlanState
	if err := json.Unmarshal(data, &decoded); err != nil { t.Fatal(err) }
	if len(decoded.Feedback) != 1 || decoded.Feedback[0].ItemID != "task:123" {
		t.Fatalf("state round trip failed: %#v", decoded)
	}
}
