package externalintel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

type ThreatPulse struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Tags     []string `json:"tags"`
	Created  string   `json:"created,omitempty"`
	Modified string   `json:"modified,omitempty"`
}

type ThreatIntelReport struct {
	Target        string        `json:"target"`
	IndicatorType string        `json:"indicator_type"`
	Source        string        `json:"source"`
	RetrievedAt   time.Time     `json:"retrieved_at"`
	PulseCount    int           `json:"pulse_count"`
	Pulses        []ThreatPulse `json:"pulses"`
	Truncated     bool          `json:"truncated"`
	Limitations   []string      `json:"limitations"`
}

type ThreatIntelClient struct {
	HTTPClient *http.Client
	BaseURL    string
	APIKey     string
	Timeout    time.Duration
	Now        func() time.Time
}

type otxGeneralResponse struct {
	Indicator string `json:"indicator"`
	Type      string `json:"type"`
	PulseInfo struct {
		Count  int `json:"count"`
		Pulses []struct {
			ID       string   `json:"id"`
			Name     string   `json:"name"`
			Tags     []string `json:"tags"`
			Created  string   `json:"created"`
			Modified string   `json:"modified"`
		} `json:"pulses"`
	} `json:"pulse_info"`
}

// Lookup queries OTX community pulse references for a domain or public IP.
// Pulse membership is treated as a report lead, never as a malware verdict.
func (c *ThreatIntelClient) Lookup(ctx context.Context, rawTarget string) (ThreatIntelReport, error) {
	if ctx == nil {
		return ThreatIntelReport{}, fmt.Errorf("context is required")
	}
	target := strings.TrimSpace(rawTarget)
	indicatorType := "domain"
	if ip := net.ParseIP(target); ip != nil {
		if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
			return ThreatIntelReport{}, fmt.Errorf("threat-intelligence lookup requires a public IP address")
		}
		target = ip.String()
		if ip.To4() != nil {
			indicatorType = "IPv4"
		} else {
			indicatorType = "IPv6"
		}
	} else {
		target = normalizeDomain(target)
		if !evidence.IsValidDomain(target) {
			return ThreatIntelReport{}, fmt.Errorf("target must be a valid DNS domain or public IP address")
		}
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	base := strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if base == "" {
		base = defaultOTXBaseURL
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return ThreatIntelReport{}, fmt.Errorf("threat-intelligence endpoint must be absolute HTTPS")
	}
	endpoint := base + "/indicators/" + url.PathEscape(indicatorType) + "/" + url.PathEscape(target) + "/general"
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	client = sameHostHTTPSClient(client, parsed)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return ThreatIntelReport{}, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "KEM3T-External-Intelligence/1.0 (research)")
	if key := strings.TrimSpace(c.APIKey); key != "" {
		req.Header.Set("X-OTX-API-KEY", key)
	}
	resp, err := doExternalRequest(ctx, client, req)
	if err != nil {
		return ThreatIntelReport{}, fmt.Errorf("query OTX threat intelligence: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		status := resp.StatusCode
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
		resp.Body.Close()
		return ThreatIntelReport{}, fmt.Errorf("OTX threat-intelligence source returned HTTP %d", status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxPassiveDNSBytes+1))
	resp.Body.Close()
	if err != nil {
		return ThreatIntelReport{}, err
	}
	if len(body) > maxPassiveDNSBytes {
		return ThreatIntelReport{}, fmt.Errorf("OTX response exceeds %d bytes", maxPassiveDNSBytes)
	}
	var raw otxGeneralResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return ThreatIntelReport{}, fmt.Errorf("decode OTX threat response: %w", err)
	}
	if raw.Indicator != "" {
		returned := strings.TrimSpace(raw.Indicator)
		if indicatorType == "domain" {
			returned = normalizeDomain(returned)
		}
		if ip := net.ParseIP(returned); ip != nil {
			returned = ip.String()
		}
		if returned != target {
			return ThreatIntelReport{}, fmt.Errorf("OTX response indicator %q does not match requested target", raw.Indicator)
		}
	}
	pulseMap := map[string]ThreatPulse{}
	for _, item := range raw.PulseInfo.Pulses {
		id, name := strings.TrimSpace(item.ID), strings.TrimSpace(item.Name)
		if id == "" || name == "" {
			continue
		}
		tags := uniqueSorted(item.Tags)
		pulse := ThreatPulse{ID: id, Name: name, Tags: tags, Created: strings.TrimSpace(item.Created), Modified: strings.TrimSpace(item.Modified)}
		if prior, exists := pulseMap[id]; exists {
			prior.Tags = uniqueSorted(append(prior.Tags, pulse.Tags...))
			if prior.Name == "" {
				prior.Name = pulse.Name
			}
			if prior.Created == "" {
				prior.Created = pulse.Created
			}
			if prior.Modified == "" {
				prior.Modified = pulse.Modified
			}
			pulseMap[id] = prior
		} else {
			pulseMap[id] = pulse
		}
	}
	pulses := make([]ThreatPulse, 0, len(pulseMap))
	for _, pulse := range pulseMap {
		pulses = append(pulses, pulse)
	}
	sort.Slice(pulses, func(i, j int) bool {
		if pulses[i].ID != pulses[j].ID {
			return pulses[i].ID < pulses[j].ID
		}
		return pulses[i].Name < pulses[j].Name
	})
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	return ThreatIntelReport{Target: target, IndicatorType: indicatorType, Source: parsed.Host, RetrievedAt: now, PulseCount: raw.PulseInfo.Count, Pulses: pulses, Truncated: raw.PulseInfo.Count > len(pulses), Limitations: []string{
		"OTX pulses are community-submitted reports; a mention is a lead to investigate, not proof that the target is malicious or compromised.",
		"A zero pulse count or empty response is not proof that an indicator is benign.",
		"Pulse counts and tags can change, be duplicated, or refer to shared infrastructure; verify the underlying evidence and time range.",
		"OTX passive DNS and pulse data share the same provider family and must not be counted as independent corroboration.",
	}}, nil
}

// RegisterThreatIntelReport stores the provider snapshot and its timestamped observation.
func RegisterThreatIntelReport(registry *evidence.Registry, report ThreatIntelReport, provenance ...evidence.ObservationProvenance) (bool, error) {
	if registry == nil {
		return false, fmt.Errorf("evidence registry is required")
	}
	target := strings.TrimSpace(report.Target)
	if ip := net.ParseIP(target); ip != nil {
		target = ip.String()
	} else {
		target = normalizeDomain(target)
	}
	if !evidence.IsValidDomain(target) && net.ParseIP(target) == nil {
		return false, fmt.Errorf("threat-intelligence target is invalid")
	}
	if strings.TrimSpace(report.Source) == "" || report.RetrievedAt.IsZero() {
		return false, fmt.Errorf("threat-intelligence source and retrieval timestamp are required")
	}
	pulses := append([]ThreatPulse(nil), report.Pulses...)
	sort.Slice(pulses, func(i, j int) bool { return pulses[i].ID < pulses[j].ID })
	details := evidence.ThreatIntelDetails{Target: target, IndicatorType: strings.TrimSpace(report.IndicatorType), Source: strings.TrimSpace(report.Source), PulseCount: report.PulseCount, Truncated: report.Truncated}
	for _, pulse := range pulses {
		if strings.TrimSpace(pulse.ID) == "" || strings.TrimSpace(pulse.Name) == "" {
			return false, fmt.Errorf("threat pulse ID and name are required")
		}
		details.Pulses = append(details.Pulses, evidence.ThreatPulseDetails{ID: strings.TrimSpace(pulse.ID), Name: strings.TrimSpace(pulse.Name), Tags: uniqueSorted(pulse.Tags), Created: strings.TrimSpace(pulse.Created), Modified: strings.TrimSpace(pulse.Modified)})
	}
	value, err := json.Marshal(details)
	if err != nil {
		return false, fmt.Errorf("encode threat-intelligence evidence: %w", err)
	}
	sum := sha256.Sum256(value)
	key := hex.EncodeToString(sum[:])
	item := evidence.Evidence{ID: "threat-intel:" + key, EntityID: target, Type: evidence.TypeThreatIntel, Value: string(value)}
	if err := registry.AddEvidence(item); err != nil && !errors.Is(err, evidence.ErrEvidenceExists) {
		return false, fmt.Errorf("register threat-intelligence evidence: %w", err)
	}
	eventID := "threat-intel:" + key + ":" + fmt.Sprint(report.RetrievedAt.UTC().UnixNano())
	observation := evidence.Observation{ID: "observation:" + eventID, EvidenceID: item.ID, Source: report.Source, ObservedAt: report.RetrievedAt.UTC(), EventIDs: []string{eventID}}
	applyRegistrationProvenance(&observation, provenance)
	if err := registry.AddObservation(observation); err != nil {
		if errors.Is(err, evidence.ErrObservationExists) {
			return false, nil
		}
		return false, fmt.Errorf("register threat-intelligence observation: %w", err)
	}
	return true, nil
}
