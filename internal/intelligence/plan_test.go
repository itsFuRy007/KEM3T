package intelligence

import "testing"

func TestBuildAdaptiveInvestigationPlanPrioritizesEvidenceGaps(t *testing.T) {
	report := IntelligenceReport{
		Target: "example.com",
		IntelligenceGaps: []IntelligenceGap{{
			ID: "gap:conflict", Kind: "EVIDENCE_CONFLICT", Subject: "example.com",
			Unknown: "Which source is reliable?", WhyItMatters: "Conflicting evidence changes the conclusion.",
			RequiredEvidence: []string{"source records"}, SuggestedAction: "Reconcile source timestamps.",
			AlternativeExplanations: "Collection delay.", Priority: "HIGH", References: []string{"evidence:a"},
		}},
		Narrative: ResearchNarrative{
			NextSteps: []NarrativeNextStep{{
				ID: "next-step:001", Action: "Review the service manually.",
				Reason: "Inspect the observed service.", References: []string{"finding:service"},
			}},
		},
		PrioritizedFindings: []PrioritizedFinding{{Finding: Finding{Title: "service"}, Priority: PriorityHigh}},
	}
	plan, err := BuildAdaptiveInvestigationPlan(report, nil, nil)
	if err != nil { t.Fatal(err) }
	if len(plan.Items) != 2 { t.Fatalf("got %d plan items, want 2", len(plan.Items)) }
	if plan.Items[0].Action != "Reconcile source timestamps." { t.Fatalf("high-priority gap was not first: %#v", plan.Items) }
	if plan.Items[0].PriorityLabel != "HIGH" { t.Fatalf("unexpected priority label: %s", plan.Items[0].PriorityLabel) }
	if err := plan.Validate(); err != nil { t.Fatalf("plan invalid: %v", err) }
	again, err := BuildAdaptiveInvestigationPlan(report, nil, nil)
	if err != nil { t.Fatal(err) }
	if plan.Revision != again.Revision || plan.Items[0].ID != again.Items[0].ID {
		t.Fatal("plan is not deterministic")
	}
}

func TestBuildAdaptiveInvestigationPlanAppliesFeedbackAndRetainsHistory(t *testing.T) {
	initial := IntelligenceReport{
		Target: "example.com",
		IntelligenceGaps: []IntelligenceGap{{
			ID: "gap:one", Kind: "INDEPENDENT_CONFIRMATION", Subject: "example.com",
			Unknown: "Need confirmation.", WhyItMatters: "Avoid a false link.",
			RequiredEvidence: []string{"independent source"}, SuggestedAction: "Collect independent ownership evidence.",
			AlternativeExplanations: "Shared hosting.", Priority: "MEDIUM", References: []string{"discovery:one"},
		}},
	}
	first, err := BuildAdaptiveInvestigationPlan(initial, nil, nil)
	if err != nil { t.Fatal(err) }
	itemID := first.Items[0].ID

	updated, err := BuildAdaptiveInvestigationPlan(IntelligenceReport{Target: "example.com"}, &first, []InvestigationFeedback{{
		ItemID: itemID, Outcome: FeedbackCompleted, EvidenceIDs: []string{"evidence:new"},
	}})
	if err != nil { t.Fatal(err) }
	if len(updated.Items) != 1 || updated.Items[0].Status != TaskCompleted {
		t.Fatalf("completed task history not retained: %#v", updated.Items)
	}
	if len(updated.Items[0].EvidenceIDs) != 1 || updated.Items[0].EvidenceIDs[0] != "evidence:new" {
		t.Fatalf("feedback evidence not retained: %#v", updated.Items[0].EvidenceIDs)
	}
	if updated.Revision == first.Revision { t.Fatal("plan revision did not change after feedback") }
}

func TestBuildAdaptiveInvestigationPlanKeepsInconclusiveWorkActive(t *testing.T) {
	report := IntelligenceReport{
		Target: "example.com",
		Narrative: ResearchNarrative{NextSteps: []NarrativeNextStep{{
			ID: "next-step:1", Action: "Inspect source records.", Reason: "Resolve uncertainty.",
			References: []string{"assessment:hypothesis-1"},
		}}},
	}
	first, err := BuildAdaptiveInvestigationPlan(report, nil, nil)
	if err != nil { t.Fatal(err) }
	next, err := BuildAdaptiveInvestigationPlan(report, &first, []InvestigationFeedback{{
		ItemID: first.Items[0].ID, Outcome: FeedbackInconclusive, Note: "Source records were incomplete.",
	}})
	if err != nil { t.Fatal(err) }
	if next.Items[0].Status != TaskInconclusive { t.Fatalf("got status %s", next.Items[0].Status) }
	if next.Items[0].Status != TaskInconclusive && next.Items[0].Status != TaskRecommended { t.Fatal("inconclusive action should remain active") }
}

func TestBuildAdaptiveInvestigationPlanRejectsInvalidFeedback(t *testing.T) {
	report := IntelligenceReport{Target: "example.com"}
	if _, err := BuildAdaptiveInvestigationPlan(report, nil, []InvestigationFeedback{{ItemID: "unknown", Outcome: FeedbackCompleted}}); err == nil {
		t.Fatal("expected unknown feedback item to be rejected")
	}
	report.Narrative.NextSteps = []NarrativeNextStep{{ID: "step", Action: "Review evidence.", Reason: "Need more context.", References: []string{"finding:one"}}}
	plan, err := BuildAdaptiveInvestigationPlan(report, nil, nil)
	if err != nil { t.Fatal(err) }
	if _, err := BuildAdaptiveInvestigationPlan(report, &plan, []InvestigationFeedback{{ItemID: plan.Items[0].ID, Outcome: FeedbackCompleted}}); err == nil {
		t.Fatal("completed feedback without evidence must be rejected")
	}
	if _, err := BuildAdaptiveInvestigationPlan(IntelligenceReport{Target: "other.example"}, &plan, nil); err == nil {
		t.Fatal("cross-target plan reuse must be rejected")
	}
}
