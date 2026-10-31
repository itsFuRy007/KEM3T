package externalintel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

const defaultRDAPBootstrapURL = "https://data.iana.org/rdap/dns.json"
const maxRDAPResponseBytes = 2 << 20

type RDAPEvent struct {
	Action string `json:"action"`
	Date   string `json:"date"`
}

// RDAPReport intentionally excludes contact addresses, emails, phone numbers,
// and postal addresses; it keeps registration metadata useful for infrastructure research.
type RDAPReport struct {
	Target      string      `json:"target"`
	Source      string      `json:"source"`
	RetrievedAt time.Time   `json:"retrieved_at"`
	Handle      string      `json:"handle,omitempty"`
	Registrar   string      `json:"registrar,omitempty"`
	Status      []string    `json:"status"`
	NameServers []string    `json:"name_servers"`
	Events      []RDAPEvent `json:"events"`
	Limitations []string    `json:"limitations"`
}

type RDAPClient struct {
	HTTPClient     *http.Client
	BootstrapURL   string
	IPBootstrapURL string
	Timeout        time.Duration
	Now            func() time.Time
}

type rdapBootstrap struct {
	Services [][]json.RawMessage `json:"services"`
}
type rdapDomainResponse struct {
	LDHName     string   `json:"ldhName"`
	Handle      string   `json:"handle"`
	Status      []string `json:"status"`
	NameServers []struct {
		LDHName string `json:"ldhName"`
	} `json:"nameservers"`
	Events []struct {
		Action string `json:"eventAction"`
		Date   string `json:"eventDate"`
	} `json:"events"`
	Entities []struct {
		Roles []string `json:"roles"`
		VCard []any    `json:"vcardArray"`
	} `json:"entities"`
}

type IPRDAPReport struct {
	Target       string    `json:"target"`
	Source       string    `json:"source"`
	RetrievedAt  time.Time `json:"retrieved_at"`
	Handle       string    `json:"handle,omitempty"`
	Name         string    `json:"name,omitempty"`
	StartAddress string    `json:"start_address"`
	EndAddress   string    `json:"end_address"`
	Country      string    `json:"country,omitempty"`
	NetworkType  string    `json:"network_type,omitempty"`
	Status       []string  `json:"status"`
	Limitations  []string  `json:"limitations"`
}
type rdapIPResponse struct {
	Handle       string   `json:"handle"`
	Name         string   `json:"name"`
	StartAddress string   `json:"startAddress"`
	EndAddress   string   `json:"endAddress"`
	Country      string   `json:"country"`
	Type         string   `json:"type"`
	Status       []string `json:"status"`
}

// LookupDomain discovers the authoritative RDAP service using IANA bootstrap data.
func (c *RDAPClient) LookupDomain(ctx context.Context, target string) (RDAPReport, error) {
	if ctx == nil {
		return RDAPReport{}, fmt.Errorf("context is required")
	}
	target = normalizeDomain(target)
	if !evidence.IsValidDomain(target) {
		return RDAPReport{}, fmt.Errorf("target must be a valid DNS domain")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("RDAP redirects must use HTTPS")
			}
			if len(via) >= 4 {
				return fmt.Errorf("too many RDAP redirects")
			}
			return nil
		}}
	}
	bootstrapURL := strings.TrimSpace(c.BootstrapURL)
	if bootstrapURL == "" {
		bootstrapURL = defaultRDAPBootstrapURL
	}
	bp, err := url.Parse(bootstrapURL)
	if err != nil || bp.Scheme != "https" || bp.Host == "" {
		return RDAPReport{}, fmt.Errorf("RDAP bootstrap URL must be an absolute HTTPS URL")
	}
	bootstrapBody, err := rdapGET(requestCtx, client, bootstrapURL)
	if err != nil {
		return RDAPReport{}, fmt.Errorf("fetch RDAP bootstrap: %w", err)
	}
	var bootstrap rdapBootstrap
	if err := json.Unmarshal(bootstrapBody, &bootstrap); err != nil {
		return RDAPReport{}, fmt.Errorf("decode RDAP bootstrap: %w", err)
	}
	serviceURL, err := selectRDAPService(bootstrap, target)
	if err != nil {
		return RDAPReport{}, err
	}
	service, err := url.Parse(serviceURL)
	if err != nil || service.Scheme != "https" || service.Host == "" {
		return RDAPReport{}, fmt.Errorf("RDAP bootstrap selected an invalid HTTPS service URL")
	}
	service.Path = strings.TrimRight(service.Path, "/") + "/domain/" + url.PathEscape(target)
	body, err := rdapGET(requestCtx, client, service.String())
	if err != nil {
		return RDAPReport{}, fmt.Errorf("query domain RDAP: %w", err)
	}
	var raw rdapDomainResponse
	if err := json.Unmarshal(body, &raw); err != nil {
		return RDAPReport{}, fmt.Errorf("decode domain RDAP response: %w", err)
	}
	if raw.LDHName != "" && normalizeDomain(raw.LDHName) != target {
		return RDAPReport{}, fmt.Errorf("RDAP response domain %q does not match requested target", raw.LDHName)
	}
	names := map[string]struct{}{}
	for _, ns := range raw.NameServers {
		name := normalizeDomain(ns.LDHName)
		if evidence.IsValidDomain(name) {
			names[name] = struct{}{}
		}
	}
	nameServers := make([]string, 0, len(names))
	for name := range names {
		nameServers = append(nameServers, name)
	}
	sort.Strings(nameServers)
	events := make([]RDAPEvent, 0, len(raw.Events))
	for _, event := range raw.Events {
		action, date := strings.TrimSpace(event.Action), strings.TrimSpace(event.Date)
		if action != "" && date != "" {
			events = append(events, RDAPEvent{Action: action, Date: date})
		}
	}
	sort.Slice(events, func(i, j int) bool {
		if events[i].Action != events[j].Action {
			return events[i].Action < events[j].Action
		}
		return events[i].Date < events[j].Date
	})
	registrar := ""
	for _, entity := range raw.Entities {
		match := false
		for _, role := range entity.Roles {
			if strings.EqualFold(role, "registrar") {
				match = true
				break
			}
		}
		if match {
			registrar = rdapRegistrarLabel(entity.VCard)
			if registrar != "" {
				break
			}
		}
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	return RDAPReport{Target: target, Source: service.Host, RetrievedAt: now, Handle: strings.TrimSpace(raw.Handle), Registrar: registrar, Status: uniqueSorted(raw.Status), NameServers: nameServers, Events: events, Limitations: []string{
		"RDAP data is registry-reported metadata and may be incomplete, delayed, redacted, or privacy-protected.",
		"A registrar label or nameserver does not independently prove who controls the infrastructure.",
		"Registration status is not a security verdict; a missing field does not prove the underlying fact does not exist.",
	}}, nil
}

func rdapGET(ctx context.Context, client *http.Client, endpoint string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create RDAP request: %w", err)
	}
	req.Header.Set("Accept", "application/rdap+json, application/json")
	req.Header.Set("User-Agent", "KEM3T-External-Intelligence/1.0 (research)")

	// Enforce HTTPS redirects even when a caller injects a custom HTTP client.
	// Clone the client so this policy does not mutate caller-owned configuration.
	safeClient := *client
	previousCheckRedirect := safeClient.CheckRedirect
	safeClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return fmt.Errorf("RDAP redirects must use HTTPS")
		}
		if len(via) >= 4 {
			return fmt.Errorf("too many RDAP redirects")
		}
		if previousCheckRedirect != nil {
			return previousCheckRedirect(req, via)
		}
		return nil
	}
	resp, err := doExternalRequest(ctx, &safeClient, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 2048))
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRDAPResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxRDAPResponseBytes {
		return nil, fmt.Errorf("response exceeds %d bytes", maxRDAPResponseBytes)
	}
	return body, nil
}

func selectRDAPService(bootstrap rdapBootstrap, target string) (string, error) {
	labels := strings.Split(target, ".")
	for start := 0; start < len(labels); start++ {
		suffix := strings.Join(labels[start:], ".")
		for _, service := range bootstrap.Services {
			if len(service) != 2 {
				continue
			}
			var suffixes, urls []string
			if json.Unmarshal(service[0], &suffixes) != nil || json.Unmarshal(service[1], &urls) != nil {
				continue
			}
			matched := false
			for _, candidate := range suffixes {
				if strings.EqualFold(strings.TrimPrefix(candidate, "."), suffix) {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
			for _, rawURL := range urls {
				parsed, err := url.Parse(strings.TrimSpace(rawURL))
				if err == nil && parsed.Scheme == "https" && parsed.Host != "" {
					return strings.TrimRight(parsed.String(), "/") + "/", nil
				}
			}
		}
	}
	return "", fmt.Errorf("IANA RDAP bootstrap has no HTTPS service for %q", target)
}

func rdapRegistrarLabel(vcard []any) string {
	if len(vcard) < 2 {
		return ""
	}
	properties, ok := vcard[1].([]any)
	if !ok {
		return ""
	}
	for _, item := range properties {
		property, ok := item.([]any)
		if !ok || len(property) < 4 {
			continue
		}
		key, _ := property[0].(string)
		if !strings.EqualFold(key, "org") && !strings.EqualFold(key, "fn") {
			continue
		}
		switch value := property[3].(type) {
		case string:
			if strings.TrimSpace(value) != "" {
				return strings.TrimSpace(value)
			}
		case []any:
			for _, part := range value {
				if s, ok := part.(string); ok && strings.TrimSpace(s) != "" {
					return strings.TrimSpace(s)
				}
			}
		}
	}
	return ""
}

func uniqueSorted(values []string) []string {
	set := map[string]struct{}{}
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

// RegisterRDAPReport stores a stable registration fact and a separate timestamped
// observation so later changes become history instead of overwriting prior evidence.
// LookupIP discovers the authoritative RIR RDAP service for an IP address.
func (c *RDAPClient) LookupIP(ctx context.Context, rawTarget string) (IPRDAPReport, error) {
	if ctx == nil {
		return IPRDAPReport{}, fmt.Errorf("context is required")
	}
	targetAddr, err := netip.ParseAddr(strings.TrimSpace(rawTarget))
	if err != nil {
		return IPRDAPReport{}, fmt.Errorf("target must be an IP address: %w", err)
	}
	if targetAddr.Zone() != "" {
		return IPRDAPReport{}, fmt.Errorf("RDAP target IP cannot include a zone identifier")
	}
	targetAddr = targetAddr.Unmap()
	target := targetAddr.String()
	ip := net.ParseIP(target)
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 12 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout, CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("RDAP redirects must use HTTPS")
			}
			if len(via) >= 4 {
				return fmt.Errorf("too many RDAP redirects")
			}
			return nil
		}}
	}
	bootstrapURL := strings.TrimSpace(c.IPBootstrapURL)
	if bootstrapURL == "" {
		if ip.To4() != nil {
			bootstrapURL = "https://data.iana.org/rdap/ipv4.json"
		} else {
			bootstrapURL = "https://data.iana.org/rdap/ipv6.json"
		}
	}
	bp, err := url.Parse(bootstrapURL)
	if err != nil || bp.Scheme != "https" || bp.Host == "" {
		return IPRDAPReport{}, fmt.Errorf("IP RDAP bootstrap URL must be absolute HTTPS")
	}
	body, err := rdapGET(ctx, client, bootstrapURL)
	if err != nil {
		return IPRDAPReport{}, fmt.Errorf("fetch IP RDAP bootstrap: %w", err)
	}
	var bootstrap rdapBootstrap
	if err := json.Unmarshal(body, &bootstrap); err != nil {
		return IPRDAPReport{}, fmt.Errorf("decode IP RDAP bootstrap: %w", err)
	}
	serviceURL, err := selectIPRDAPService(bootstrap, ip)
	if err != nil {
		return IPRDAPReport{}, err
	}
	service, err := url.Parse(serviceURL)
	if err != nil || service.Scheme != "https" || service.Host == "" {
		return IPRDAPReport{}, fmt.Errorf("IP RDAP bootstrap selected an invalid HTTPS service")
	}
	service.Path = strings.TrimRight(service.Path, "/") + "/ip/" + url.PathEscape(target)
	response, err := rdapGET(ctx, client, service.String())
	if err != nil {
		return IPRDAPReport{}, fmt.Errorf("query IP RDAP: %w", err)
	}
	var raw rdapIPResponse
	if err := json.Unmarshal(response, &raw); err != nil {
		return IPRDAPReport{}, fmt.Errorf("decode IP RDAP response: %w", err)
	}
	_, start, end, err := validateIPRDAPRange(target, raw.StartAddress, raw.EndAddress)
	if err != nil {
		return IPRDAPReport{}, err
	}
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	return IPRDAPReport{Target: target, Source: service.Host, RetrievedAt: now, Handle: strings.TrimSpace(raw.Handle), Name: strings.TrimSpace(raw.Name), StartAddress: start.String(), EndAddress: end.String(), Country: strings.TrimSpace(raw.Country), NetworkType: strings.TrimSpace(raw.Type), Status: uniqueSorted(raw.Status), Limitations: []string{
		"IP RDAP describes a registry allocation/assignment range; it does not prove which customer currently operates a host.",
		"Network names and country fields are registry-provided labels and may be absent, broad, or stale.",
		"A registered network range is context, not a security or reputation verdict.",
	}}, nil
}

func validateIPRDAPRange(target, startAddress, endAddress string) (netip.Addr, netip.Addr, netip.Addr, error) {
	targetAddr, err := netip.ParseAddr(strings.TrimSpace(target))
	if err != nil {
		return netip.Addr{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("RDAP target IP is invalid: %w", err)
	}
	if targetAddr.Zone() != "" {
		return netip.Addr{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("RDAP target IP cannot include a zone identifier")
	}
	targetAddr = targetAddr.Unmap()
	start, err := netip.ParseAddr(strings.TrimSpace(startAddress))
	if err != nil {
		return netip.Addr{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("RDAP start address is invalid: %w", err)
	}
	if start.Zone() != "" {
		return netip.Addr{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("RDAP start address cannot include a zone identifier")
	}
	start = start.Unmap()
	end, err := netip.ParseAddr(strings.TrimSpace(endAddress))
	if err != nil {
		return netip.Addr{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("RDAP end address is invalid: %w", err)
	}
	if end.Zone() != "" {
		return netip.Addr{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("RDAP end address cannot include a zone identifier")
	}
	end = end.Unmap()
	if start.Is4() != targetAddr.Is4() || end.Is4() != targetAddr.Is4() || start.Compare(end) > 0 || targetAddr.Compare(start) < 0 || targetAddr.Compare(end) > 0 {
		return netip.Addr{}, netip.Addr{}, netip.Addr{}, fmt.Errorf("RDAP network range does not contain requested IP")
	}
	return targetAddr, start, end, nil
}

func selectIPRDAPService(bootstrap rdapBootstrap, ip net.IP) (string, error) {
	bestBits := -1
	bestURL := ""
	for _, service := range bootstrap.Services {
		if len(service) != 2 {
			continue
		}
		var prefixes, urls []string
		if json.Unmarshal(service[0], &prefixes) != nil || json.Unmarshal(service[1], &urls) != nil {
			continue
		}
		for _, rawPrefix := range prefixes {
			_, prefix, err := net.ParseCIDR(strings.TrimSpace(rawPrefix))
			if err != nil || !prefix.Contains(ip) {
				continue
			}
			bits, _ := prefix.Mask.Size()
			if bits <= bestBits {
				continue
			}
			for _, rawURL := range urls {
				u, err := url.Parse(strings.TrimSpace(rawURL))
				if err == nil && u.Scheme == "https" && u.Host != "" {
					bestBits = bits
					bestURL = strings.TrimRight(u.String(), "/") + "/"
					break
				}
			}
		}
	}
	if bestURL == "" {
		return "", fmt.Errorf("IANA IP RDAP bootstrap has no HTTPS service for %s", ip.String())
	}
	return bestURL, nil
}

func RegisterRDAPReport(registry *evidence.Registry, report RDAPReport, provenance ...evidence.ObservationProvenance) (bool, error) {
	if registry == nil {
		return false, fmt.Errorf("evidence registry is required")
	}
	target := normalizeDomain(report.Target)
	if !evidence.IsValidDomain(target) {
		return false, fmt.Errorf("RDAP report target is invalid")
	}
	source := strings.TrimSpace(report.Source)
	if source == "" {
		return false, fmt.Errorf("RDAP report source is required")
	}
	if report.RetrievedAt.IsZero() {
		return false, fmt.Errorf("RDAP retrieval timestamp is required")
	}
	details := evidence.RDAPRegistrationDetails{Target: target, Handle: strings.TrimSpace(report.Handle), Registrar: strings.TrimSpace(report.Registrar), Status: uniqueSorted(report.Status), NameServers: uniqueSorted(report.NameServers)}
	for i, ns := range details.NameServers {
		details.NameServers[i] = normalizeDomain(ns)
		if !evidence.IsValidDomain(details.NameServers[i]) {
			return false, fmt.Errorf("invalid RDAP nameserver %q", ns)
		}
	}
	for _, event := range report.Events {
		action, date := strings.TrimSpace(event.Action), strings.TrimSpace(event.Date)
		if action != "" && date != "" {
			details.Events = append(details.Events, evidence.RDAPRegistrationEvent{Action: action, Date: date})
		}
	}
	sort.Slice(details.Events, func(i, j int) bool {
		if details.Events[i].Action != details.Events[j].Action {
			return details.Events[i].Action < details.Events[j].Action
		}
		return details.Events[i].Date < details.Events[j].Date
	})
	value, err := json.Marshal(details)
	if err != nil {
		return false, fmt.Errorf("encode RDAP evidence: %w", err)
	}
	sum := sha256.Sum256(value)
	key := hex.EncodeToString(sum[:])
	item := evidence.Evidence{ID: "rdap-registration:" + key, EntityID: target, Type: evidence.TypeRDAPRegistration, Value: string(value)}
	eventID := "rdap:" + key + ":" + fmt.Sprint(report.RetrievedAt.UTC().UnixNano())
	observation := evidence.Observation{ID: "observation:" + eventID, EvidenceID: item.ID, Source: source, ObservedAt: report.RetrievedAt.UTC(), EventIDs: []string{eventID}}
	applyRegistrationProvenance(&observation, provenance)
	added, err := registerEvidenceObservation(registry, item, observation)
	if err != nil {
		return false, fmt.Errorf("register RDAP evidence batch: %w", err)
	}
	return added, nil
}

func RegisterIPRDAPReport(registry *evidence.Registry, report IPRDAPReport, provenance ...evidence.ObservationProvenance) (bool, error) {
	if registry == nil {
		return false, fmt.Errorf("evidence registry is required")
	}
	targetAddr, start, end, err := validateIPRDAPRange(report.Target, report.StartAddress, report.EndAddress)
	if err != nil {
		return false, err
	}
	ip := net.ParseIP(targetAddr.String())
	source := strings.TrimSpace(report.Source)
	if source == "" || report.RetrievedAt.IsZero() {
		return false, fmt.Errorf("IP RDAP source and retrieval timestamp are required")
	}
	details := evidence.IPRDAPNetworkDetails{Target: ip.String(), Handle: strings.TrimSpace(report.Handle), Name: strings.TrimSpace(report.Name), StartAddress: start.String(), EndAddress: end.String(), Country: strings.TrimSpace(report.Country), NetworkType: strings.TrimSpace(report.NetworkType), Status: uniqueSorted(report.Status)}
	value, err := json.Marshal(details)
	if err != nil {
		return false, fmt.Errorf("encode IP RDAP evidence: %w", err)
	}
	sum := sha256.Sum256(value)
	key := hex.EncodeToString(sum[:])
	item := evidence.Evidence{ID: "ip-rdap-network:" + key, EntityID: ip.String(), Type: evidence.TypeIPRDAPNetwork, Value: string(value)}
	eventID := "ip-rdap-network:" + key + ":" + fmt.Sprint(report.RetrievedAt.UTC().UnixNano())
	observation := evidence.Observation{ID: "observation:" + eventID, EvidenceID: item.ID, Source: source, ObservedAt: report.RetrievedAt.UTC(), EventIDs: []string{eventID}}
	applyRegistrationProvenance(&observation, provenance)
	added, err := registerEvidenceObservation(registry, item, observation)
	if err != nil {
		return false, fmt.Errorf("register IP RDAP evidence batch: %w", err)
	}
	return added, nil
}
