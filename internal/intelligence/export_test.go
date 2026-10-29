package intelligence

import (
	"encoding/json"
	"strings"
	"testing"
)

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

func TestInvestigationExportJSONContract(t *testing.T) {
	export := NewInvestigationExport("example.com", &IntelligenceReport{Target: "example.com"})
	data, err := json.Marshal(export)
	if err != nil {
		t.Fatalf("marshal export: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal export: %v", err)
	}
	if decoded["schema_version"] != ExportSchemaVersion {
		t.Fatalf("schema_version = %v, want %q", decoded["schema_version"], ExportSchemaVersion)
	}
	investigation, ok := decoded["investigation"].(map[string]any)
	if !ok {
		t.Fatalf("investigation section has unexpected type: %T", decoded["investigation"])
	}
	if investigation["target"] != "example.com" {
		t.Fatalf("target = %v, want example.com", investigation["target"])
	}
	if _, ok := decoded["report"].(map[string]any); !ok {
		t.Fatalf("report section has unexpected type: %T", decoded["report"])
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
