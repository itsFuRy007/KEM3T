package externalintel

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"encoding/hex"
	"errors"
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
	defaultCTEndpoint = "https://crt.sh/"
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
	query := parsed.Query()
	query.Set("q", "%."+target)
	query.Set("output", "json")
	parsed.RawQuery = query.Encode()

	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	requestCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(requestCtx, http.MethodGet, parsed.String(), nil)
	if err != nil {
		return CTReport{}, fmt.Errorf("create CT request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "KEM3T-External-Intelligence/1.0 (research)")

	client := c.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	resp, err := doExternalRequest(ctx, client, req)
	if err != nil {
		return CTReport{}, fmt.Errorf("query Certificate Transparency source: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return CTReport{}, fmt.Errorf("CT source returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCTResponseBytes+1))
	if err != nil {
		return CTReport{}, fmt.Errorf("read CT response: %w", err)
	}
	if len(body) > maxCTResponseBytes {
		return CTReport{}, fmt.Errorf("CT response exceeds %d bytes", maxCTResponseBytes)
	}
	var rows []crtSHRow
	if err := json.Unmarshal(body, &rows); err != nil {
		return CTReport{}, fmt.Errorf("decode CT response: %w", err)
	}

	recordsByID := make(map[int]CTRecord)
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
		if row.ID <= 0 {
			// Some compatible endpoints omit IDs. Preserve the row deterministically
			// without pretending it is a verified unique certificate.
			record.CertificateID = 0
			recordsByID[len(recordsByID)*-1-1] = record
		} else if prior, exists := recordsByID[row.ID]; exists {
			recordsByID[row.ID] = mergeCTRecords(prior, record)
		} else {
			recordsByID[row.ID] = record
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
	for _, name := range a.DNSNames { names[name] = struct{}{} }
	for _, name := range b.DNSNames { names[name] = struct{}{} }
	a.DNSNames = a.DNSNames[:0]
	for name := range names { a.DNSNames = append(a.DNSNames, name) }
	sort.Strings(a.DNSNames)
	if a.CommonName == "" { a.CommonName = b.CommonName }
	if a.IssuerName == "" { a.IssuerName = b.IssuerName }
	if a.NotBefore == "" { a.NotBefore = b.NotBefore }
	if a.NotAfter == "" { a.NotAfter = b.NotAfter }
	return a
}

 
// RegisterCTReport persists certificate-name observations with stable evidence
// IDs and timestamped observation IDs, allowing repeated queries to extend
// provenance history without duplicating the underlying fact.
func RegisterCTReport(registry *evidence.Registry, report CTReport) (int, error) {
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

	added := 0
	for _, record := range report.Records {
		for _, rawName := range record.DNSNames {
			name := normalizeDomain(rawName)
			if !evidence.IsValidDomain(name) || !inDomainScope(name, target) {
				return added, fmt.Errorf("CT report contains out-of-scope name %q", rawName)
			}
			details := evidence.CTDNSNameDetails{
				Target: target, DNSName: name, CertificateID: record.CertificateID,
				IssuerName: strings.TrimSpace(record.IssuerName),
				NotBefore: strings.TrimSpace(record.NotBefore), NotAfter: strings.TrimSpace(record.NotAfter),
				Source: source, RetrievedAt: report.RetrievedAt.UTC(),
			}
			value, err := json.Marshal(details)
			if err != nil {
				return added, fmt.Errorf("encode CT evidence: %w", err)
			}
			sum := sha256.Sum256(value)
			factKey := hex.EncodeToString(sum[:])
			item := evidence.Evidence{
				ID: "ct-dns-name:" + factKey, EntityID: target,
				Type: evidence.TypeCTDNSName, Value: string(value),
			}
			if err := registry.AddEvidence(item); err != nil && !errors.Is(err, evidence.ErrEvidenceExists) {
				return added, fmt.Errorf("register CT evidence: %w", err)
			}
			eventID := "ct:" + factKey + ":" + fmt.Sprint(report.RetrievedAt.UTC().UnixNano())
			observation := evidence.Observation{
				ID: "observation:" + eventID, EvidenceID: item.ID, Source: source,
				ObservedAt: report.RetrievedAt.UTC(), EventIDs: []string{eventID},
			}
			if err := registry.AddObservation(observation); err != nil {
				if errors.Is(err, evidence.ErrObservationExists) {
					continue
				}
				return added, fmt.Errorf("register CT observation: %w", err)
			}
			added++
		}
	}
	return added, nil
}
