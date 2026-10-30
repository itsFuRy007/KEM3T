package observations

import (
	"fmt"
	"strings"
	"time"
)

type Service struct {
	ID string `json:"id"`
	Target string `json:"target"`
	Port int `json:"port"`
	Transport string `json:"transport"`
	Application string `json:"application,omitempty"`
	State string `json:"state"`
	EvidenceIDs []string `json:"evidence_ids,omitempty"`
	Sources []string `json:"sources,omitempty"`
	ObservedAt time.Time `json:"observed_at"`
	Indicators map[string]string `json:"indicators,omitempty"`
}

func IdentifyService(observation Observation, evidenceIDs ...string) (Service, error) {
	if strings.TrimSpace(observation.Target) == "" { return Service{}, fmt.Errorf("observation target is required") }
	if observation.Port < 1 || observation.Port > 65535 { return Service{}, fmt.Errorf("service port must be between 1 and 65535") }
	if observation.Kind != KindTCPPort && observation.Kind != KindTLSCertificate && observation.Kind != KindHTTPService { return Service{}, fmt.Errorf("observation kind %q does not describe a service", observation.Kind) }

	service := Service{Target: observation.Target, Port: observation.Port, Transport: "tcp", State: "observed", EvidenceIDs: uniqueSorted(evidenceIDs), Sources: []string{observation.Source}, ObservedAt: observation.ObservedAt, Indicators: make(map[string]string)}
	switch observation.Kind {
	case KindTCPPort:
		state := strings.ToLower(strings.TrimSpace(observation.Value))
		if state != "open" && state != "closed" && state != "unknown" { return Service{}, fmt.Errorf("unsupported TCP service state %q", state) }
		service.State = state
		service.Indicators["tcp_state"] = state
	case KindTLSCertificate:
		service.Indicators["tls_certificate_sha256"] = observation.Value
		service.Indicators["tls_observed"] = "true"
	case KindHTTPService:
		service.Application = observation.Protocol
		service.Indicators["http_status_code"] = observation.Value
		service.Indicators["scheme"] = observation.Protocol
	}
	for key, value := range observation.Attributes { if value != "" { service.Indicators[key] = value } }
	service.ID = fmt.Sprintf("service:%s:%d:%s", service.Target, service.Port, service.Application)
	if service.Application == "" { service.ID = fmt.Sprintf("service:%s:%d:%s", service.Target, service.Port, service.State) }
	return service, nil
}

func uniqueSorted(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values { value = strings.TrimSpace(value); if value != "" { set[value] = struct{}{} } }
	out := make([]string, 0, len(set))
	for value := range set { out = append(out, value) }
	for i := 1; i < len(out); i++ { for j := i; j > 0 && out[j] < out[j-1]; j-- { out[j], out[j-1] = out[j-1], out[j] } }
	return out
}
