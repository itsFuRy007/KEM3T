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
