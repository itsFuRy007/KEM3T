package observations

import (
	"fmt"
	"sort"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/events"
)

type Collection struct {
	Observations []Observation `json:"observations"`
	Services     []Service     `json:"services"`
	Rejected     []Rejection   `json:"rejected,omitempty"`
}

type Rejection struct {
	EventID string `json:"event_id"`
	Reason  string `json:"reason"`
}

func NormalizeEvents(input []events.Event) Collection {
	result := Collection{Observations: make([]Observation, 0, len(input)), Services: make([]Service, 0), Rejected: make([]Rejection, 0)}
	for _, event := range input {
		observation, err := Normalize(event)
		if err != nil {
			result.Rejected = append(result.Rejected, Rejection{EventID: strings.TrimSpace(event.ID), Reason: err.Error()})
			continue
		}
		result.Observations = append(result.Observations, observation)
	}
	sort.Slice(result.Observations, func(i, j int) bool {
		if result.Observations[i].Target != result.Observations[j].Target {
			return result.Observations[i].Target < result.Observations[j].Target
		}
		if result.Observations[i].Port != result.Observations[j].Port {
			return result.Observations[i].Port < result.Observations[j].Port
		}
		if result.Observations[i].Kind != result.Observations[j].Kind {
			return result.Observations[i].Kind < result.Observations[j].Kind
		}
		return result.Observations[i].EventID < result.Observations[j].EventID
	})
	sort.Slice(result.Rejected, func(i, j int) bool {
		if result.Rejected[i].EventID != result.Rejected[j].EventID {
			return result.Rejected[i].EventID < result.Rejected[j].EventID
		}
		return result.Rejected[i].Reason < result.Rejected[j].Reason
	})
	result.Services = BuildServices(result.Observations)
	return result
}

func BuildServices(input []Observation) []Service {
	byID := make(map[string]Service)
	tcpObservedAt := make(map[string]time.Time)
	for _, observation := range input {
		service, err := IdentifyService(observation)
		if err != nil {
			continue
		}
		key := fmt.Sprintf("%s:%d", service.Target, service.Port)
		current, exists := byID[key]
		if !exists {
			current = Service{Target: service.Target, Port: service.Port, Transport: "tcp", State: "observed", Indicators: make(map[string]string)}
		}
		if observation.Kind == KindTCPPort {
			lastTCP, seenTCP := tcpObservedAt[key]
			if !seenTCP || observation.ObservedAt.After(lastTCP) {
				current.State = service.State
				tcpObservedAt[key] = observation.ObservedAt
			}
		}
		if service.Application != "" {
			current.Application = service.Application
		}
		if current.ObservedAt.IsZero() || observation.ObservedAt.After(current.ObservedAt) {
			current.ObservedAt = observation.ObservedAt
		}
		if observation.Source != "" {
			current.Sources = appendUniqueString(current.Sources, observation.Source)
		}
		for _, evidenceID := range observation.EvidenceIDs {
			current.EvidenceIDs = appendUniqueString(current.EvidenceIDs, evidenceID)
		}
		for key, value := range service.Indicators {
			if value != "" {
				current.Indicators[key] = value
			}
		}
		byID[key] = current
	}
	result := make([]Service, 0, len(byID))
	for _, service := range byID {
		sort.Strings(service.Sources)
		sort.Strings(service.EvidenceIDs)
		if service.Application == "" {
			service.ID = fmt.Sprintf("service:%s:%d:unknown", service.Target, service.Port)
		} else {
			service.ID = fmt.Sprintf("service:%s:%d:%s", service.Target, service.Port, service.Application)
		}
		result = append(result, service)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ID < result[j].ID })
	return result
}

func appendUniqueString(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}
