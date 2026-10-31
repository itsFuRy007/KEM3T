package investigation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/itsFuRy007/kem3t/internal/collectors"
	"github.com/itsFuRy007/kem3t/internal/events"
	"github.com/itsFuRy007/kem3t/internal/evidence"
	"github.com/itsFuRy007/kem3t/internal/intelligence"
)

type eventCollector interface {
	Run(context.Context, chan<- events.Event) error
}

type CollectorStage struct {
	StageName string
	Collector eventCollector
	Convert   func(events.Event) (evidence.Evidence, evidence.Observation, error)
	Accept    func(events.Event) bool
	Analyze   func(events.Event) (*intelligence.Finding, error)
}

func (s *CollectorStage) Name() string { return strings.TrimSpace(s.StageName) }

func (s *CollectorStage) Run(ctx context.Context, target string, registry *evidence.Registry) (StageResult, error) {
	if ctx == nil {
		return StageResult{}, fmt.Errorf("context is required")
	}
	if registry == nil {
		return StageResult{}, fmt.Errorf("shared evidence registry is required")
	}
	if s == nil || s.Collector == nil {
		return StageResult{}, fmt.Errorf("collector is required")
	}
	if s.Convert == nil {
		return StageResult{}, fmt.Errorf("event converter is required")
	}
	if strings.TrimSpace(target) == "" {
		return StageResult{}, fmt.Errorf("target is required")
	}

	stageCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	eventCh := make(chan events.Event)
	done := make(chan error, 1)
	go func() {
		err := s.Collector.Run(stageCtx, eventCh)
		close(eventCh)
		done <- err
	}()

	result := StageResult{}
	pendingEvidence := make([]evidence.Evidence, 0)
	pendingObservations := make([]evidence.Observation, 0)
	seenEvidence := make(map[string]struct{})
	seenObservations := make(map[string]struct{})
	var registrationErr error
	for event := range eventCh {
		if err := stageCtx.Err(); err != nil {
			registrationErr = err
			break
		}
		if err := event.Validate(); err != nil {
			registrationErr = fmt.Errorf("collector %q emitted invalid event: %w", s.Name(), err)
			cancel()
			break
		}
		if !eventTargetInScope(event.Target, target) {
			registrationErr = fmt.Errorf("collector %q emitted out-of-scope target %q", s.Name(), event.Target)
			cancel()
			break
		}
		if s.Accept != nil && !s.Accept(event) {
			continue
		}

		if s.Analyze != nil {
			finding, err := s.Analyze(event)
			if err != nil {
				registrationErr = fmt.Errorf("analyze %s event: %w", s.Name(), err)
				cancel()
				break
			}
			if finding != nil {
				result.Findings = append(result.Findings, *finding)
			}
		}

		result.Events++
		item, observation, err := s.Convert(event)
		if err != nil {
			registrationErr = fmt.Errorf("convert %s event: %w", s.Name(), err)
			cancel()
			break
		}

		evidence.ApplyObservationProvenance(stageCtx, &observation)

		// Buffer stage output and commit it atomically only after the collector
		// completes successfully. A failed stage must not leave partial evidence
		// that later stages or reports could mistake for a complete collection.
		if _, exists := seenEvidence[item.ID]; !exists {
			if _, lookupErr := registry.GetEvidence(item.ID); errors.Is(lookupErr, evidence.ErrEvidenceNotFound) {
				pendingEvidence = append(pendingEvidence, item)
				seenEvidence[item.ID] = struct{}{}
			} else if lookupErr != nil {
				registrationErr = fmt.Errorf("check existing %s evidence: %w", s.Name(), lookupErr)
				cancel()
				break
			}
		}
		if _, exists := seenObservations[observation.ID]; !exists {
			if _, lookupErr := registry.GetObservation(observation.ID); errors.Is(lookupErr, evidence.ErrObservationNotFound) {
				pendingObservations = append(pendingObservations, observation)
				seenObservations[observation.ID] = struct{}{}
			} else if lookupErr != nil {
				registrationErr = fmt.Errorf("check existing %s observation: %w", s.Name(), lookupErr)
				cancel()
				break
			}
		}
	}
	collectorErr := <-done
	if registrationErr != nil {
		result.Findings = nil
		return result, registrationErr
	}
	if err := stageCtx.Err(); err != nil {
		result.Findings = nil
		return result, err
	}
	if collectorErr != nil {
		result.Findings = nil
		return result, fmt.Errorf("%s collector: %w", s.Name(), collectorErr)
	}
	if err := registry.AddBatch(ctx, pendingEvidence, pendingObservations); err != nil {
		result.Findings = nil
		return result, fmt.Errorf("commit %s stage evidence atomically: %w", s.Name(), err)
	}
	result.Evidence = len(pendingEvidence)
	result.Observations = len(pendingObservations)
	return result, nil
}

func NewDNSStage(target string) *CollectorStage { return NewDNSStageWithResolver(target, nil) }

func NewDNSStageWithResolver(target string, resolver collectors.DNSResolver) *CollectorStage {
	return newDNSStage("dns", target, resolver)
}

func NewDNSSubdomainStage(target string) *CollectorStage {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	return newDNSStage("dns-subdomain:"+name, name, nil)
}

func newDNSStage(name, target string, resolver collectors.DNSResolver) *CollectorStage {
	return &CollectorStage{
		StageName: name,
		Collector: &collectors.DNS{Target: target, Resolver: resolver},
		Accept:    func(event events.Event) bool { return event.Type == events.EventDNSRecordFound },
		Convert:   evidence.FromDNSEvent,
		Analyze:   (&intelligence.Engine{}).Analyze,
	}
}

func NewTCPStage(target string, startPort, endPort int) *CollectorStage {
	return &CollectorStage{
		StageName: "tcp",
		Collector: &collectors.TCP{Target: target, StartPort: startPort, EndPort: endPort},
		Accept: func(event events.Event) bool {
			return event.Type == events.EventPortDiscovered || event.Type == events.EventTCPPortStateObserved
		},
		Convert: evidence.FromTCPEvent,
		Analyze: (&intelligence.Engine{}).Analyze,
	}
}

func NewTLSStage(target string, port int) *CollectorStage {
	if port == 0 {
		port = 443
	}
	return &CollectorStage{
		StageName: "tls",
		Collector: &collectors.TLS{Target: target, Port: port},
		Accept:    func(event events.Event) bool { return event.Type == events.EventTLSCertificateFound },
		Convert:   evidence.FromTLSEvent,
		Analyze:   (&intelligence.Engine{}).Analyze,
	}
}

func NewHTTPStage(target, scheme string, port int) *CollectorStage {
	return &CollectorStage{
		StageName: "http",
		Collector: &collectors.HTTP{Target: target, Scheme: scheme, Port: port},
		Accept:    func(event events.Event) bool { return event.Type == events.EventHTTPObserved },
		Convert:   evidence.FromHTTPEvent,
		Analyze:   (&intelligence.Engine{}).Analyze,
	}
}

func eventTargetInScope(eventTarget, target string) bool {
	eventTarget = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(eventTarget)), ".")
	target = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), ".")
	if eventTarget == "" || target == "" {
		return false
	}
	if eventTarget == target {
		return true
	}
	if net.ParseIP(target) != nil {
		return false
	}
	return strings.HasSuffix(eventTarget, "."+target)
}
