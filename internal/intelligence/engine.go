package intelligence

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

type Engine struct{}

func (e *Engine) Analyze(event events.Event) (*Finding, error) {
	if err := event.Validate(); err != nil {
		return nil, fmt.Errorf("invalid event: %w", err)
	}

	switch event.Type {
	case events.EventSubdomainDiscovered:
		return analyzeSubdomain(event), nil
	case events.EventDNSRecordFound:
		return analyzeDNSRecord(event)
	case events.EventPortDiscovered, events.EventTCPPortStateObserved:
		return analyzeTCPPort(event)
	case events.EventTLSCertificateFound:
		return analyzeTLSCertificate(event)
	default:
		return nil, nil
	}
}

func (e *Engine) AnalyzeAll(eventsIn []events.Event) ([]Finding, error) {
	findings := make([]Finding, 0, len(eventsIn))
	for _, event := range eventsIn {
		finding, err := e.Analyze(event)
		if err != nil {
			return nil, fmt.Errorf("analyze event %q: %w", event.ID, err)
		}
		if finding != nil {
			findings = append(findings, *finding)
		}
	}
	return findings, nil
}

func analyzeSubdomain(event events.Event) *Finding {
	hostname := strings.ToLower(strings.TrimSpace(event.Target))
	finding := &Finding{
		Title:     "Subdomain discovered",
		Priority:  PriorityInfo,
		Fact:      fmt.Sprintf("The hostname %s was discovered.", event.Target),
		Evidence:  []events.Event{event},
		NextSteps: []string{"Verify the asset and inspect its DNS records."},
	}
	labels := strings.Split(hostname, ".")
	for _, label := range labels {
		switch label {
		case "dev", "development", "staging", "stage", "test", "qa":
			finding.Title = "Development-related hostname observed"
			finding.Priority = PriorityInterest
			finding.Observation = fmt.Sprintf("The hostname contains the label %q.", label)
			finding.PossibleSignificance = "It may indicate development or staging infrastructure; the hostname alone does not confirm its purpose."
			finding.NextSteps = []string{"Verify the asset and resolve its DNS records.", "Identify exposed services before drawing further conclusions."}
			return finding
		}
	}
	finding.Observation = "No development-related label was detected."
	finding.PossibleSignificance = "The hostname alone does not establish whether the asset is sensitive."
	return finding
}

func analyzeDNSRecord(event events.Event) (*Finding, error) {
	recordType := strings.ToUpper(strings.TrimSpace(event.Data["record_type"]))
	value := strings.TrimSpace(event.Data["value"])
	if recordType != "IP_ADDRESS" {
		return nil, nil
	}
	ip := net.ParseIP(value)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address %q in DNS event", value)
	}
	return &Finding{
		Title:    "DNS address resolved",
		Priority: PriorityInfo,
		Fact: fmt.Sprintf("The resolver returned IP address %s for hostname %s.", ip.String(), event.Target),
		Observation: "An IP address was returned by the configured DNS resolver.",
		PossibleSignificance: "This associates the hostname with a resolved address at the time of collection; it does not establish that the address is vulnerable.",
		Evidence:  []events.Event{event},
		NextSteps: []string{"Verify the address and collect authorized service information."},
	}, nil
}

func (e *Engine) Run(ctx context.Context, input <-chan events.Event, output chan<- Finding) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case event, ok := <-input:
			if !ok {
				return nil
			}
			finding, err := e.Analyze(event)
			if err != nil {
				return fmt.Errorf("analyze event %q: %w", event.ID, err)
			}
			if finding == nil {
				continue
			}
			select {
			case output <- *finding:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
}

func analyzeTCPPort(event events.Event) (*Finding, error) {
	protocol := strings.ToLower(strings.TrimSpace(event.Data["protocol"]))
	state := strings.ToLower(strings.TrimSpace(event.Data["state"]))
	portText := strings.TrimSpace(event.Data["port"])
	if protocol != "tcp" {
		return nil, fmt.Errorf("unsupported transport protocol %q in port event", protocol)
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid TCP port %q", portText)
	}

	switch state {
	case "open":
		return &Finding{
			Title: "Open TCP port observed", Priority: PriorityInfo,
			Fact: fmt.Sprintf("TCP port %d was observed open on %s.", port, strings.TrimSpace(event.Target)),
			Observation: "A TCP connection to this port succeeded during collection.",
			PossibleSignificance: "The port may expose a network service; an open port alone does not establish that the service is vulnerable.",
			Evidence: []events.Event{event},
			NextSteps: []string{"Identify the service and version using authorized collection.", "Determine whether the service is expected to be reachable.", "Review service configuration and access controls before drawing security conclusions."},
		}, nil
	case "closed":
		return &Finding{
			Title: "Closed TCP port observed", Priority: PriorityInfo,
			Fact: fmt.Sprintf("TCP port %d was observed closed on %s.", port, strings.TrimSpace(event.Target)),
			Observation: "The TCP connection attempt was actively refused.",
			PossibleSignificance: "The host appears reachable on this port but no TCP service accepted the connection at collection time.",
			Evidence: []events.Event{event},
			NextSteps: []string{"Record the closed state as baseline information.", "Recheck later if service exposure is expected to change."},
		}, nil
	case "unknown":
		reason := strings.TrimSpace(event.Data["reason"])
		if reason == "" {
			reason = "the connection attempt was inconclusive"
		}
		return &Finding{
			Title: "TCP port state unknown", Priority: PriorityInterest,
			Fact: fmt.Sprintf("TCP port %d could not be classified as open or closed on %s.", port, strings.TrimSpace(event.Target)),
			Observation: fmt.Sprintf("The collector reported an inconclusive connection attempt: %s.", reason),
			PossibleSignificance: "The port may be filtered, unreachable, rate-limited, or otherwise inconclusive; UNKNOWN must not be interpreted as CLOSED.",
			Evidence: []events.Event{event},
			NextSteps: []string{"Do not infer port closure from this result.", "Recheck with an appropriate authorized probe if the port is important to the investigation."},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported TCP port state %q", state)
	}
}

func analyzeTLSCertificate(event events.Event) (*Finding, error) {
	portText := strings.TrimSpace(event.Data["port"])
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid TLS port %q", portText)
	}
	notAfter, err := time.Parse(time.RFC3339, strings.TrimSpace(event.Data["not_after"]))
	if err != nil {
		return nil, fmt.Errorf("invalid TLS certificate expiry timestamp: %w", err)
	}
	verified, err := strconv.ParseBool(strings.TrimSpace(event.Data["verified"]))
	if err != nil {
		return nil, fmt.Errorf("invalid TLS certificate verification status: %w", err)
	}
	version := strings.TrimSpace(event.Data["tls_version"])
	if version == "" {
		return nil, fmt.Errorf("TLS version is required")
	}
	priority := PriorityInfo
	title := "TLS certificate observed"
	fact := fmt.Sprintf("A TLS certificate was observed on %s:%d using %s.", strings.TrimSpace(event.Target), port, version)
	observation := "Certificate verification succeeded."
	significance := "The certificate metadata describes the TLS endpoint at collection time; it does not by itself establish the security of the service."
	nextSteps := []string{"Review certificate identity and hostname coverage.", "Review the negotiated TLS version and service configuration."}
	if !notAfter.After(event.Timestamp) {
		priority = PriorityInterest
		title = "TLS certificate expired or expiring at observation time"
		fact = fmt.Sprintf("The TLS certificate for %s:%d had an expiry time of %s, which was not after the collection timestamp.", strings.TrimSpace(event.Target), port, notAfter.UTC().Format(time.RFC3339))
		observation = "The certificate expiry timestamp is at or before the event timestamp."
		significance = "An expired certificate can cause client trust warnings or failed connections; confirm the endpoint's current certificate before remediation."
		nextSteps = []string{"Recheck the endpoint to confirm the current certificate and expiry.", "If still expired, renew and deploy the certificate through the authorized service owner."}
	} else if !verified {
		priority = PriorityInterest
		title = "TLS certificate verification did not succeed"
		observation = "The collector reported that certificate verification did not succeed."
		significance = "Possible causes include an untrusted chain, hostname mismatch, or other validation failure; the exact cause must be verified."
		nextSteps = []string{"Inspect the certificate chain and hostname match.", "Determine the specific verification failure before recommending remediation."}
	}
	return &Finding{Title: title, Priority: priority, Fact: fact, Observation: observation, PossibleSignificance: significance, Evidence: []events.Event{event}, NextSteps: nextSteps}, nil
}
