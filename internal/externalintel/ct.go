package externalintel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

const (
	defaultCTEndpoint  = "https://crt.sh/"
	maxCTResponseBytes = 4 << 20
)

// CTRecord is a certificate-transparency observation returned by crt.sh.
// DNSNames are normalized, in-scope names only; certificate rows are not proof
// that the names share an owner or operational control.
type CTRecord struct {
	CertificateID int      `json:"certificate_id"`
	CommonName    string   `json:"common_name,omitempty"`
	DNSNames      []string `json:"dns_names"`
	IssuerName    string   `json:"issuer_name,omitempty"`
	NotBefore     string   `json:"not_before,omitempty"`
	NotAfter      string   `json:"not_after,omitempty"`
}

// CTReport summarizes public Certificate Transparency observations for a domain.
type CTReport struct {
	Target             string     `json:"target"`
	Source             string     `json:"source"`
	RetrievedAt        time.Time  `json:"retrieved_at"`
	CertificateRecords int        `json:"certificate_records"`
	UniqueDNSNames     int        `json:"unique_dns_names"`
	UniqueIssuers      int        `json:"unique_issuers"`
	DNSNames           []string   `json:"dns_names"`
	Records            []CTRecord `json:"records"`
	Limitations        []string   `json:"limitations"`
}

// CTClient queries a public Certificate Transparency search endpoint.
// HTTPClient and Endpoint are injectable so tests do not need network access.
type CTClient struct {
	HTTPClient *http.Client
	Endpoint   string
	Timeout    time.Duration
	Now        func() time.Time
}

type crtSHRow struct {
	ID         int    `json:"id"`
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
	IssuerName string `json:"issuer_name"`
	NotBefore  string `json:"not_before"`
	NotAfter   string `json:"not_after"`
}

// LookupDomain returns certificate records and the unique in-scope DNS names
// seen in their SAN/common-name fields. It never treats CT presence as proof
// of current hosting, ownership, or vulnerability.
func (c *CTClient) LookupDomain(ctx context.Context, target string) (CTReport, error) {
	if ctx == nil {
		return CTReport{}, fmt.Errorf("context is required")
	}
	target = normalizeDomain(target)
	if !evidence.IsValidDomain(target) {
		return CTReport{}, fmt.Errorf("target must be a valid DNS domain")
	}

	endpoint := strings.TrimSpace(c.Endpoint)
	if endpoint == "" {
		endpoint = defaultCTEndpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" {
		return CTReport{}, fmt.Errorf("CT endpoint must be an absolute HTTPS URL")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	rows := make([]crtSHRow, 0)
	for _, queryValue := range []string{target, "%." + target} {
		queryURL := *parsed
		query := queryURL.Query()
		query.Set("q", queryValue)
		query.Set("output", "json")
		queryURL.RawQuery = query.Encode()

		req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, queryURL.String(), nil)
		if err != nil {
			return CTReport{}, fmt.Errorf("create CT request for %q: %w", queryValue, err)
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "KEM3T-External-Intelligence/1.0 (research)")

		resp, err := doExternalRequest(requestCtx, client, req)
		if err != nil {
			return CTReport{}, fmt.Errorf("query Certificate Transparency source for %q: %w", queryValue, err)
		}
		if resp.StatusCode != http.StatusOK {
			_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
			_ = resp.Body.Close()
			return CTReport{}, fmt.Errorf("CT source returned HTTP %d for query %q", resp.StatusCode, queryValue)
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxCTResponseBytes+1))
		_ = resp.Body.Close()
		if err != nil {
			return CTReport{}, fmt.Errorf("read CT response for %q: %w", queryValue, err)
		}
		if len(body) > maxCTResponseBytes {
			return CTReport{}, fmt.Errorf("CT response for %q exceeds %d bytes", queryValue, maxCTResponseBytes)
		}
		var queryRows []crtSHRow
		if err := json.Unmarshal(body, &queryRows); err != nil {
			return CTReport{}, fmt.Errorf("decode CT response for %q: %w", queryValue, err)
		}
		rows = append(rows, queryRows...)
	}

	recordsByID := make(map[string]CTRecord)
	names := make(map[string]struct{})
	issuers := make(map[string]struct{})
	for _, row := range rows {
		nameSet := make(map[string]struct{})
		for _, raw := range append(strings.Split(row.NameValue, "\n"), row.CommonName) {
			name := normalizeDomain(raw)
			if strings.HasPrefix(name, "*.") {
				name = strings.TrimPrefix(name, "*.")
			}
			if !inDomainScope(name, target) || !evidence.IsValidDomain(name) {
				continue
			}
			nameSet[name] = struct{}{}
		}
		if len(nameSet) == 0 {
			continue
		}
		dnsNames := make([]string, 0, len(nameSet))
		for name := range nameSet {
			dnsNames = append(dnsNames, name)
			names[name] = struct{}{}
		}
		sort.Strings(dnsNames)
		commonName := normalizeDomain(row.CommonName)
		if strings.HasPrefix(commonName, "*.") {
			commonName = strings.TrimPrefix(commonName, "*.")
		}
		if !inDomainScope(commonName, target) || !evidence.IsValidDomain(commonName) {
			commonName = ""
		}
		record := CTRecord{
			CertificateID: row.ID,
			CommonName:    commonName,
			DNSNames:      dnsNames,
			IssuerName:    strings.TrimSpace(row.IssuerName),
			NotBefore:     strings.TrimSpace(row.NotBefore),
			NotAfter:      strings.TrimSpace(row.NotAfter),
		}
		key := ""
		if row.ID > 0 {
			key = fmt.Sprintf("id:%d", row.ID)
		} else {
			// Compatible endpoints may omit certificate IDs. Deduplicate identical
			// rows returned by the apex and wildcard queries using normalized content,
			// while keeping ID-less records distinct from provider-identified records.
			record.CertificateID = 0
			fingerprint, err := json.Marshal(record)
			if err != nil {
				return CTReport{}, fmt.Errorf("fingerprint CT row without certificate ID: %w", err)
			}
			sum := sha256.Sum256(fingerprint)
			key = "content:" + hex.EncodeToString(sum[:])
		}
		if prior, exists := recordsByID[key]; exists {
			recordsByID[key] = mergeCTRecords(prior, record)
		} else {
			recordsByID[key] = record
		}
		if issuer := strings.TrimSpace(row.IssuerName); issuer != "" {
			issuers[issuer] = struct{}{}
		}
	}
	records := make([]CTRecord, 0, len(recordsByID))
	for _, record := range recordsByID {
		records = append(records, record)
	}
	sort.Slice(records, func(i, j int) bool {
		if records[i].CertificateID != records[j].CertificateID {
			return records[i].CertificateID < records[j].CertificateID
		}
		return strings.Join(records[i].DNSNames, ",") < strings.Join(records[j].DNSNames, ",")
	})
	dnsNames := make([]string, 0, len(names))
	for name := range names {
		dnsNames = append(dnsNames, name)
	}
	sort.Strings(dnsNames)
	now := time.Now().UTC()
	if c.Now != nil {
		now = c.Now().UTC()
	}
	return CTReport{
		Target: target, Source: parsed.Host, RetrievedAt: now,
		CertificateRecords: len(records), UniqueDNSNames: len(dnsNames),
		UniqueIssuers: len(issuers), DNSNames: dnsNames, Records: records,
		Limitations: []string{
			"Certificate Transparency records show certificate issuance/publication, not proof of current DNS resolution or a live service.",
			"Shared certificates or SANs do not establish common ownership or operational control.",
			"Absence from this source is not proof that no certificate exists.",
		},
	}, nil
}

func normalizeDomain(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	value = strings.TrimSuffix(value, ".")
	return value
}

func inDomainScope(name, target string) bool {
	return name == target || strings.HasSuffix(name, "."+target)
}

func mergeCTRecords(a, b CTRecord) CTRecord {
	names := make(map[string]struct{}, len(a.DNSNames)+len(b.DNSNames))
	for _, name := range a.DNSNames {
		names[name] = struct{}{}
	}
	for _, name := range b.DNSNames {
		names[name] = struct{}{}
	}
	a.DNSNames = a.DNSNames[:0]
	for name := range names {
		a.DNSNames = append(a.DNSNames, name)
	}
	sort.Strings(a.DNSNames)
	if a.CommonName == "" {
		a.CommonName = b.CommonName
	}
	if a.IssuerName == "" {
		a.IssuerName = b.IssuerName
	}
	if a.NotBefore == "" {
		a.NotBefore = b.NotBefore
	}
	if a.NotAfter == "" {
		a.NotAfter = b.NotAfter
	}
	return a
}

// RegisterCTReport persists certificate-name observations with stable evidence
// IDs and timestamped observation IDs, allowing repeated queries to extend
// provenance history without duplicating the underlying fact.
func RegisterCTReport(registry *evidence.Registry, report CTReport, provenance ...evidence.ObservationProvenance) (int, error) {
	if registry == nil {
		return 0, fmt.Errorf("evidence registry is required")
	}
	target := normalizeDomain(report.Target)
	if !evidence.IsValidDomain(target) {
		return 0, fmt.Errorf("CT report target is invalid")
	}
	source := strings.TrimSpace(report.Source)
	if source == "" {
		return 0, fmt.Errorf("CT report source is required")
	}
	if report.RetrievedAt.IsZero() {
		return 0, fmt.Errorf("CT report retrieval timestamp is required")
	}

	pendingEvidence := make([]evidence.Evidence, 0)
	pendingObservations := make([]evidence.Observation, 0)
	for _, record := range report.Records {
		for _, rawName := range record.DNSNames {
			name := normalizeDomain(rawName)
			if !evidence.IsValidDomain(name) || !inDomainScope(name, target) {
				return 0, fmt.Errorf("CT report contains out-of-scope name %q", rawName)
			}
			details := evidence.CTDNSNameDetails{
				Target: target, DNSName: name, CertificateID: record.CertificateID,
				IssuerName: strings.TrimSpace(record.IssuerName),
				NotBefore:  strings.TrimSpace(record.NotBefore), NotAfter: strings.TrimSpace(record.NotAfter),
				Source: source, RetrievedAt: report.RetrievedAt.UTC(),
			}
			value, err := json.Marshal(details)
			if err != nil {
				return 0, fmt.Errorf("encode CT evidence: %w", err)
			}
			// Evidence identity describes the certificate/name fact, not the
			// time at which this source happened to be queried. Retrieval time
			// remains on the value/provenance observation, while the ID stays
			// stable across repeated collections.
			identity, err := json.Marshal(struct {
				Target        string `json:"target"`
				DNSName       string `json:"dns_name"`
				CertificateID int    `json:"certificate_id"`
				IssuerName    string `json:"issuer_name,omitempty"`
				NotBefore     string `json:"not_before,omitempty"`
				NotAfter      string `json:"not_after,omitempty"`
				Source        string `json:"source"`
			}{target, name, record.CertificateID, details.IssuerName, details.NotBefore, details.NotAfter, source})
			if err != nil {
				return 0, fmt.Errorf("encode CT fact identity: %w", err)
			}
			sum := sha256.Sum256(identity)
			factKey := hex.EncodeToString(sum[:])
			item := evidence.Evidence{
				ID: "ct-dns-name:" + factKey, EntityID: target,
				Type: evidence.TypeCTDNSName, Value: string(value),
			}
			eventID := "ct:" + factKey + ":" + fmt.Sprint(report.RetrievedAt.UTC().UnixNano())
			observation := evidence.Observation{
				ID: "observation:" + eventID, EvidenceID: item.ID, Source: source,
				ObservedAt: report.RetrievedAt.UTC(), EventIDs: []string{eventID},
			}
			applyRegistrationProvenance(&observation, provenance)
			pendingEvidence = append(pendingEvidence, item)
			pendingObservations = append(pendingObservations, observation)
		}
	}
	added, err := registerEvidenceObservations(registry, pendingEvidence, pendingObservations)
	if err != nil {
		return 0, fmt.Errorf("register CT evidence batch: %w", err)
	}
	return added, nil
}
