package evidence

import "testing"

func validEvidence() Evidence {
	return Evidence{
		ID:       "ev-001",
		EntityID: "api.example.test",
		Type:     TypeDNSAddress,
		Value:    "192.0.2.10",
	}
}

func TestEvidenceValidate(t *testing.T) {
	if err := validEvidence().Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
}

func TestEvidenceValidateRejectsMissingFields(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Evidence)
	}{
		{"missing ID", func(e *Evidence) { e.ID = "" }},
		{"missing entity", func(e *Evidence) { e.EntityID = "" }},
		{"invalid type", func(e *Evidence) { e.Type = "UNKNOWN" }},
		{"missing value", func(e *Evidence) { e.Value = "" }},
		{"invalid IP", func(e *Evidence) { e.Value = "999.999.999.999" }},
		{"hostname instead of IP", func(e *Evidence) { e.Value = "api.example.test" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := validEvidence()
			tt.mutate(&e)
			if err := e.Validate(); err == nil {
				t.Fatal("Validate() expected an error")
			}
		})
	}

}

func TestEvidenceValidateAcceptsIPv6(t *testing.T) {
	e := validEvidence()
	e.Value = "2001:db8::10"

	if err := e.Validate(); err != nil {
		t.Fatalf("Validate() rejected valid IPv6 address: %v", err)
	}

}

func TestEvidenceValidateAcceptsTrimmedIP(t *testing.T) {
	e := validEvidence()
	e.Value = " 192.0.2.10 "

	if err := e.Validate(); err != nil {
		t.Fatalf("Validate() rejected IP with surrounding whitespace: %v", err)
	}

}
