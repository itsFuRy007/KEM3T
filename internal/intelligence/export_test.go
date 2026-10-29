package intelligence

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/changes"
	"github.com/itsFuRy007/kem3t/internal/snapshots"
)

func testSnapshot(target string, collected time.Time, addresses ...string) snapshots.Snapshot {
	return snapshots.Snapshot{Target: target, Collected: collected, Addresses: addresses}
}

func TestNewInvestigationExport(t *testing.T) {
	report := &IntelligenceReport{Target: "example.com"}
	export := NewInvestigationExport("example.com", report)

	if export.SchemaVersion != ExportSchemaVersion {
		t.Fatalf("schema version = %q, want %q", export.SchemaVersion, ExportSchemaVersion)
	}
	if export.Investigation.Target != "example.com" {
		t.Fatalf("target = %q, want example.com", export.Investigation.Target)
	}
	if export.Report != report {
		t.Fatal("report pointer was not preserved")
	}
	if err := export.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestDNSInvestigationExportPreservesTemporalContext(t *testing.T) {
	previousTime := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	currentTime := previousTime.Add(time.Hour)
	previous := testSnapshot("example.com", previousTime, "192.0.2.1", "192.0.2.2")
	current := testSnapshot("example.com", currentTime, "192.0.2.1", "192.0.2.3")
	history := &DNSHistoryComparison{
		Target: "example.com", Added: []string{"192.0.2.3"},
		Removed: []string{"192.0.2.2"}, Unchanged: []string{"192.0.2.1"},
		PreviousCount: 2, CurrentCount: 2,
	}
	detected := []changes.Change{
		{Target: "example.com", Type: changes.AddressRemoved, Address: "192.0.2.2"},
		{Target: "example.com", Type: changes.AddressAdded, Address: "192.0.2.3"},
	}

	export := NewDNSInvestigationExport(
		"example.com", &IntelligenceReport{Target: "example.com"},
		current, &previous, detected, history, false,
	)
	if err := export.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal temporal export: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("decode temporal export: %v", err)
	}
	collection, ok := decoded["collection"].(map[string]any)
	if !ok {
		t.Fatalf("collection has unexpected type: %T", decoded["collection"])
	}
	if collection["baseline_created"] != false {
		t.Fatalf("baseline_created = %v, want false", collection["baseline_created"])
	}
	if _, ok := collection["previous_snapshot"].(map[string]any); !ok {
		t.Fatalf("previous_snapshot missing or malformed: %T", collection["previous_snapshot"])
	}
	changesJSON, ok := collection["changes"].([]any)
	if !ok || len(changesJSON) != 2 {
		t.Fatalf("changes = %#v, want two records", collection["changes"])
	}
	historyJSON, ok := collection["history"].(map[string]any)
	if !ok {
		t.Fatalf("history has unexpected type: %T", collection["history"])
	}
	if _, ok := historyJSON["removed_between_snapshots"]; !ok {
		t.Fatal("history does not clarify snapshot-relative removals")
	}
	if _, exists := historyJSON["removed"]; exists {
		t.Fatal("ambiguous legacy removed key unexpectedly present")
	}
}

func TestDNSInvestigationExportBaselineHasNoTemporalComparison(t *testing.T) {
	current := testSnapshot(
		"example.com",
		time.Date(2026, 10, 30, 10, 0, 0, 0, time.UTC),
		"192.0.2.1",
	)
	export := NewDNSInvestigationExport(
		"example.com", &IntelligenceReport{Target: "example.com"},
		current, nil, nil, nil, true,
	)
	if err := export.Validate(); err != nil {
		t.Fatalf("baseline Validate() error = %v", err)
	}
	if export.Collection.History != nil || len(export.Collection.Changes) != 0 {
		t.Fatal("baseline export unexpectedly contains a temporal comparison")
	}
}

func TestDNSInvestigationExportRejectsInconsistentTemporalContext(t *testing.T) {
	oldTime := time.Date(2026, 10, 29, 10, 0, 0, 0, time.UTC)
	newTime := oldTime.Add(time.Hour)
	previous := testSnapshot("example.com", oldTime, "192.0.2.1")
	current := testSnapshot("example.com", newTime, "192.0.2.1")
	validHistory := &DNSHistoryComparison{
		Target: "example.com", Added: []string{}, Removed: []string{},
		Unchanged: []string{"192.0.2.1"}, PreviousCount: 1, CurrentCount: 1,
	}
	tests := []struct {
		name string
		export InvestigationExport
		want string
	}{
		{
			name: "snapshot scope mismatch",
			export: NewDNSInvestigationExport(
				"example.com", &IntelligenceReport{Target: "example.com"},
				testSnapshot("other.example", newTime, "192.0.2.1"),
				&previous, nil, validHistory, false,
			),
			want: "current snapshot target",
		},
		{
			name: "previous snapshot newer",
			export: NewDNSInvestigationExport(
				"example.com", &IntelligenceReport{Target: "example.com"},
				previous, &current, nil,
				&DNSHistoryComparison{Target: "example.com", PreviousCount: 1, CurrentCount: 1}, false,
			),
			want: "newer than current",
		},
		{
			name: "history count mismatch",
			export: NewDNSInvestigationExport(
				"example.com", &IntelligenceReport{Target: "example.com"},
				current, &previous, nil,
				&DNSHistoryComparison{Target: "example.com", PreviousCount: 2, CurrentCount: 1}, false,
			),
			want: "counts do not match",
		},
		{
			name: "history address mismatch",
			export: NewDNSInvestigationExport(
				"example.com", &IntelligenceReport{Target: "example.com"},
				current, &previous, nil,
				&DNSHistoryComparison{Target: "example.com", Added: []string{"192.0.2.99"}, Removed: []string{}, Unchanged: []string{}, PreviousCount: 1, CurrentCount: 1}, false,
			),
			want: "address sets do not match",
		},
		{
			name: "detected change mismatch",
			export: NewDNSInvestigationExport(
				"example.com", &IntelligenceReport{Target: "example.com"},
				current, &previous,
				[]changes.Change{{Target: "example.com", Type: changes.AddressAdded, Address: "192.0.2.99"}},
				validHistory, false,
			),
			want: "detected changes do not match",
		},
		{
			name: "baseline with previous snapshot",
			export: NewDNSInvestigationExport(
				"example.com", &IntelligenceReport{Target: "example.com"},
				current, &previous, nil, validHistory, true,
			),
			want: "baseline collection cannot include",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.export.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tt.want)
			}
			if _, err := json.Marshal(tt.export); err == nil {
				t.Fatal("MarshalJSON accepted inconsistent temporal context")
			}
		})
	}
}

func TestInvestigationExportRejectsInvalidScope(t *testing.T) {
	tests := []struct {
		name   string
		export InvestigationExport
		want   string
	}{
		{
			name:   "missing target",
			export: NewInvestigationExport(" ", &IntelligenceReport{Target: "example.com"}),
			want:   "target is required",
		},
		{
			name:   "missing report",
			export: NewInvestigationExport("example.com", nil),
			want:   "report is required",
		},
		{
			name:   "missing report target",
			export: NewInvestigationExport("example.com", &IntelligenceReport{}),
			want:   "report target is required",
		},
		{
			name:   "mismatched scope",
			export: NewInvestigationExport("example.com", &IntelligenceReport{Target: "other.example"}),
			want:   "does not match",
		},
		{
			name: "unsupported schema",
			export: InvestigationExport{
				SchemaVersion: ExportSchemaVersion + ".unsupported",
				Investigation: ExportInvestigation{Target: "example.com"},
				Report:        &IntelligenceReport{Target: "example.com"},
			},
			want: "unsupported export schema",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.export.Validate()
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("Validate() error = %v, want containing %q", err, tt.want)
			}
			if _, err := json.Marshal(tt.export); err == nil {
				t.Fatal("MarshalJSON accepted invalid export")
			}
		})
	}
}

func TestStableStringSliceDoesNotMutateInput(t *testing.T) {
	input := []string{"b", "a", "c"}
	got := StableStringSlice(input)
	want := []string{"a", "b", "c"}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	if input[0] != "b" || input[1] != "a" || input[2] != "c" {
		t.Fatalf("input was mutated: %#v", input)
	}
}
