package evidence

import (
	"strings"
	"testing"
	"time"
)

var fuzzTimestamp = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

// FuzzEvidenceValidate exercises the untrusted serialized evidence boundary.
// The seed corpus covers every supported evidence type plus malformed and
// deeply nested JSON so regressions are found by ordinary go test and fuzz runs.
func FuzzEvidenceValidate(f *testing.F) {
	seeds := []struct {
		kind   string
		entity string
		value  string
	}{
		{"DNS_ADDRESS", "example.com", "192.0.2.1"},
		{"DNS_ADDRESS", "example.com", "not-an-ip"},
		{"TLS_CERTIFICATE", "example.com", `{"target":"example.com","port":443,"sha256_fingerprint":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`},
		{"TCP_PORT", "example.com", `{"target":"example.com","protocol":"tcp","port":443,"state":"open"}`},
		{"HTTP_SERVICE", "example.com", `{"target":"example.com","scheme":"https","port":443,"url":"https://example.com","final_url":"https://example.com","status_code":200}`},
		{"CT_DNS_NAME", "example.com", `{"target":"example.com","dns_name":"www.example.com","certificate_id":1,"source":"crt.sh","retrieved_at":"2026-01-01T00:00:00Z"}`},
		{"RDAP_REGISTRATION", "example.com", `{"target":"example.com","name_servers":["ns1.example.com"]}`},
		{"ASN_ORIGIN", "192.0.2.1", `{"target":"192.0.2.1","records":[{"asn":64500,"prefix":"192.0.2.0/24","mapping_source":"test","rdap_source":"test"}]}`},
		{"PASSIVE_DNS", "example.com", `{"target":"example.com","hostname":"www.example.com","address":"192.0.2.1","record_type":"A","source":"test"}`},
		{"THREAT_INTEL", "example.com", `{"target":"example.com","indicator_type":"domain","source":"test","pulse_count":0,"pulses":[]}`},
		{"IP_RDAP_NETWORK", "192.0.2.1", `{"target":"192.0.2.1","start_address":"192.0.2.0","end_address":"192.0.2.255"}`},
		{"UNKNOWN", "example.com", ""},
		{"HTTP_SERVICE", "example.com", "{\"nested\":[[[[[\""},
	}
	for _, seed := range seeds {
		f.Add(seed.kind, seed.entity, seed.value)
	}

	f.Fuzz(func(t *testing.T, kind, entity, value string) {
		// Keep fuzz cases bounded: the goal is parser/validator robustness,
		// not unbounded memory consumption from an oversized generated input.
		if len(kind) > 256 || len(entity) > 1024 || len(value) > 64*1024 {
			t.Skip()
		}
		_ = (Evidence{ID: "fuzz:evidence", EntityID: entity, Type: Type(kind), Value: value}).Validate()
	})
}

// FuzzObservationValidate exercises validation of untrusted observation
// metadata, including empty, duplicate, and malformed event references.
func FuzzObservationValidate(f *testing.F) {
	f.Add("observation:1", "evidence:1", "dns", "event:1,event:2")
	f.Add("", "", "", "")
	f.Add("observation:2", "evidence:2", "source", "event:1,event:1")
	f.Add("observation:3", "evidence:3", "source", " , , ")

	f.Fuzz(func(t *testing.T, id, evidenceID, source, rawEvents string) {
		if len(id) > 1024 || len(evidenceID) > 1024 || len(source) > 1024 || len(rawEvents) > 4096 {
			t.Skip()
		}
		var eventIDs []string
		if rawEvents != "" {
			for _, item := range splitFuzzEvents(rawEvents) {
				eventIDs = append(eventIDs, item)
			}
		}
		_ = (Observation{ID: id, EvidenceID: evidenceID, Source: source, ObservedAt: fuzzTimestamp, EventIDs: eventIDs}).Validate()
	})
}

// splitFuzzEvents deliberately avoids additional parsing dependencies while
// allowing arbitrary separators and whitespace to reach Observation.Validate.
func splitFuzzEvents(value string) []string {
	return strings.Split(value, ",")
}
