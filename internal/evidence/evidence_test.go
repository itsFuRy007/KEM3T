package evidence

import (
	"encoding/json"
	"testing"
)

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

func TestEvidenceValidateRejectsInvalidDomains(t *testing.T) {
	tests := []struct {
		name   string
		domain string
	}{
		{"empty label", "api..example.com"},
		{"leading hyphen", "-api.example.com"},
		{"trailing hyphen", "api-.example.com"},
		{"space", "api example.com"},
		{"IP address", "192.0.2.10"},
		{"underscore", "api_name.example.com"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := validEvidence()
			e.EntityID = tt.domain
			if err := e.Validate(); err == nil {
				t.Fatalf("Validate() accepted invalid domain %q", tt.domain)
			}
		})
	}
}

func TestIsValidDomain(t *testing.T) {
	valid := []string{
		"example.com",
		"api.example.test",
		"localhost",
		"api.example.com.",
	}
	for _, domain := range valid {
		if !IsValidDomain(domain) {
			t.Errorf("IsValidDomain(%q) = false, want true", domain)
		}
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

func makeIPRDAPEvidence(target, start, end string) Evidence {
	details := IPRDAPNetworkDetails{Target: target, StartAddress: start, EndAddress: end}
	value, _ := json.Marshal(details)
	return Evidence{ID: "ip-rdap:test", EntityID: target, Type: TypeIPRDAPNetwork, Value: string(value)}
}

func TestIPRDAPEvidenceRejectsNonCanonicalAddresses(t *testing.T) {
	tests := []struct {
		name      string
		evidence  Evidence
		wantValid bool
	}{
		{"valid IPv4 range", makeIPRDAPEvidence("192.0.2.10", "192.0.2.0", "192.0.2.255"), true},
		{"zone on target", makeIPRDAPEvidence("fe80::1%eth0", "fe80::", "fe80::ffff"), false},
		{"mapped IPv4 target", makeIPRDAPEvidence("::ffff:192.0.2.10", "::ffff:192.0.2.0", "::ffff:192.0.2.255"), false},
		{"zone on range start", makeIPRDAPEvidence("fe80::1", "fe80::%eth0", "fe80::ffff"), false},
		{"mapped IPv4 range end", makeIPRDAPEvidence("192.0.2.10", "192.0.2.0", "::ffff:192.0.2.255"), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.evidence.Validate()
			if test.wantValid && err != nil {
				t.Fatalf("valid evidence rejected: %v", err)
			}
			if !test.wantValid && err == nil {
				t.Fatal("expected non-canonical IP RDAP address to be rejected")
			}
		})
	}
}


func makeHTTPServiceEvidence(target, rawURL, finalURL string) Evidence {
	details := HTTPServiceDetails{
		Target: target, Scheme: "https", Port: 443,
		URL: rawURL, FinalURL: finalURL, StatusCode: 200,
	}
	value, _ := json.Marshal(details)
	return Evidence{ID: "http:test", EntityID: target, Type: TypeHTTPService, Value: string(value)}
}

func TestHTTPServiceEvidenceEnforcesTargetScope(t *testing.T) {
	tests := []struct {
		name string
		item Evidence
		wantValid bool
	}{
		{"same target", makeHTTPServiceEvidence("example.com", "https://example.com:443/", "https://example.com:443/"), true},
		{"URL host mismatch", makeHTTPServiceEvidence("example.com", "https://attacker.test/", "https://example.com/"), false},
		{"final URL host mismatch", makeHTTPServiceEvidence("example.com", "https://example.com/", "https://attacker.test/"), false},
		{"URL credentials", makeHTTPServiceEvidence("example.com", "https://user:secret@example.com/", "https://example.com/"), false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.item.Validate()
			if test.wantValid && err != nil {
				t.Fatalf("valid evidence rejected: %v", err)
			}
			if !test.wantValid && err == nil {
				t.Fatal("expected out-of-scope HTTP evidence to be rejected")
			}
		})
	}
}
