package intelligence

import (
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/evidence"
)

// ServiceSurface joins transport and application-layer observations only when
// their normalized target and port match. It is an endpoint-level view, not a
// claim that observations came from the same process or backend.
type ServiceSurface struct {
	ID              string                   `json:"id"`
	Target          string                   `json:"target"`
	Port            int                      `json:"port"`
	TCPStates       []string                 `json:"tcp_states"`
	HTTP            []ServiceHTTPObservation `json:"http_observations"`
	TLS             []ServiceTLSObservation  `json:"tls_observations"`
	Protocols       []string                 `json:"protocols"`
	EvidenceIDs     []string                 `json:"evidence_ids"`
	ObservationIDs  []string                 `json:"observation_ids"`
	ObservationRefs []ServiceObservationRef  `json:"observation_refs"`
	ReferenceRunID  string                   `json:"reference_run_id,omitempty"`
	TemporalScope   string                   `json:"temporal_scope"`
	Summary         string                   `json:"summary"`
	Limitations     []string                 `json:"limitations"`
	NextSteps       []string                 `json:"next_steps"`
}

type ServiceHTTPObservation struct {
	EvidenceID  string `json:"evidence_id"`
	Scheme      string `json:"scheme"`
	StatusCode  int    `json:"status_code"`
	Title       string `json:"title,omitempty"`
	Server      string `json:"server,omitempty"`
	FinalURL    string `json:"final_url"`
	TLSVersion  string `json:"tls_version,omitempty"`
	TLSVerified bool   `json:"tls_verified"`
}

type ServiceTLSObservation struct {
	EvidenceID  string    `json:"evidence_id"`
	Fingerprint string    `json:"sha256_fingerprint"`
	Subject     string    `json:"subject,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	TLSVersion  string    `json:"tls_version"`
	Verified    bool      `json:"verified"`
	NotAfter    time.Time `json:"not_after"`
}

type ServiceObservationRef struct {
	EvidenceID      string    `json:"evidence_id"`
	ObservationID   string    `json:"observation_id"`
	Source          string    `json:"source"`
	CollectionRunID string    `json:"collection_run_id,omitempty"`
	Stage           string    `json:"stage,omitempty"`
	ReferenceRun    bool      `json:"reference_run"`
	ObservedAt      time.Time `json:"observed_at"`
}

// BuildServiceSurfaces builds endpoint-level views from durable evidence. It
// never joins records by target alone: both normalized target and port must
// match, preventing unrelated services on different ports from being merged.
func BuildServiceSurfaces(target string, records []evidence.Evidence, observations []evidence.Observation, referenceRunIDs ...string) ([]ServiceSurface, error) {
	target = normalizeFindingTarget(target)
	if target == "" {
		return nil, fmt.Errorf("service-surface target is required")
	}
	referenceRunID := ""
	if len(referenceRunIDs) > 0 {
		referenceRunID = strings.TrimSpace(referenceRunIDs[0])
	}

	// Validate and retain observations only when they belong to evidence that
	// can contribute to this target's service surfaces. Historical records for
	// unrelated targets must not poison an otherwise valid target report.
	scopedEvidenceIDs := make(map[string]struct{}, len(records))
	for _, item := range records {
		entity := normalizeFindingTarget(item.EntityID)
		if entity != "" && serviceTargetInScope(entity, target) {
			scopedEvidenceIDs[item.ID] = struct{}{}
		}
	}
	observationsByEvidence := make(map[string][]evidence.Observation)
	seenObservationIDs := make(map[string]struct{}, len(observations))
	for _, observation := range observations {
		if _, relevant := scopedEvidenceIDs[observation.EvidenceID]; !relevant {
			continue
		}
		if err := observation.Validate(); err != nil {
			return nil, fmt.Errorf("invalid service-surface observation %q: %w", observation.ID, err)
		}
		if _, exists := seenObservationIDs[observation.ID]; exists {
			return nil, fmt.Errorf("duplicate service-surface observation ID %q", observation.ID)
		}
		seenObservationIDs[observation.ID] = struct{}{}
		observationsByEvidence[observation.EvidenceID] = append(observationsByEvidence[observation.EvidenceID], observation)
	}

	type surfaceKey struct {
		target string
		port   int
	}
	surfaces := make(map[surfaceKey]*ServiceSurface)
	evidenceIDs := make(map[surfaceKey]map[string]struct{})
	observationIDs := make(map[surfaceKey]map[string]struct{})
	ensure := func(entity string, port int) *ServiceSurface {
		key := surfaceKey{target: entity, port: port}
		if surfaces[key] == nil {
			surfaces[key] = &ServiceSurface{
				ID:     fmt.Sprintf("service-surface:%s:%d", entity, port),
				Target: entity, Port: port,
				TCPStates: []string{}, HTTP: []ServiceHTTPObservation{}, TLS: []ServiceTLSObservation{},
				Protocols: []string{}, EvidenceIDs: []string{}, ObservationIDs: []string{},
				ObservationRefs: []ServiceObservationRef{}, Limitations: []string{}, NextSteps: []string{},
			}
			evidenceIDs[key] = make(map[string]struct{})
			observationIDs[key] = make(map[string]struct{})
		}
		return surfaces[key]
	}

	for _, item := range records {
		entity := normalizeFindingTarget(item.EntityID)
		if entity == "" || !serviceTargetInScope(entity, target) {
			continue
		}
		if err := item.Validate(); err != nil {
			return nil, fmt.Errorf("invalid service-surface evidence %q: %w", item.ID, err)
		}
		var port int
		var surface *ServiceSurface
		switch item.Type {
		case evidence.TypeTCPPort:
			var details evidence.TCPPortDetails
			if err := json.Unmarshal([]byte(item.Value), &details); err != nil {
				return nil, fmt.Errorf("decode TCP evidence %q: %w", item.ID, err)
			}
			port = details.Port
			surface = ensure(entity, port)
			surface.TCPStates = append(surface.TCPStates, strings.ToUpper(details.State))
		case evidence.TypeTCPPortObservation:
			var details evidence.TCPPortObservationDetails
			if err := json.Unmarshal([]byte(item.Value), &details); err != nil {
				return nil, fmt.Errorf("decode TCP observation %q: %w", item.ID, err)
			}
			port = details.Port
			surface = ensure(entity, port)
			surface.TCPStates = append(surface.TCPStates, strings.ToUpper(details.State))
		case evidence.TypeHTTPService:
			var details evidence.HTTPServiceDetails
			if err := json.Unmarshal([]byte(item.Value), &details); err != nil {
				return nil, fmt.Errorf("decode HTTP evidence %q: %w", item.ID, err)
			}
			port = details.Port
			surface = ensure(entity, port)
			surface.HTTP = append(surface.HTTP, ServiceHTTPObservation{
				EvidenceID: item.ID, Scheme: details.Scheme, StatusCode: details.StatusCode,
				Title: details.Title, Server: details.Server, FinalURL: details.FinalURL,
				TLSVersion: details.TLSVersion, TLSVerified: details.TLSVerified,
			})
		case evidence.TypeTLSCertificate:
			var details evidence.TLSCertificateDetails
			if err := json.Unmarshal([]byte(item.Value), &details); err != nil {
				return nil, fmt.Errorf("decode TLS evidence %q: %w", item.ID, err)
			}
			port = details.Port
			surface = ensure(entity, port)
			surface.TLS = append(surface.TLS, ServiceTLSObservation{
				EvidenceID: item.ID, Fingerprint: strings.ToLower(strings.TrimSpace(details.SHA256Fingerprint)),
				Subject: details.Subject, Issuer: details.Issuer, TLSVersion: details.TLSVersion,
				Verified: details.Verified, NotAfter: details.NotAfter,
			})
		default:
			continue
		}

		key := surfaceKey{target: entity, port: port}
		evidenceIDs[key][item.ID] = struct{}{}
		for _, observation := range observationsByEvidence[item.ID] {
			observationIDs[key][observation.ID] = struct{}{}
			surface.ObservationRefs = append(surface.ObservationRefs, ServiceObservationRef{
				EvidenceID: item.ID, ObservationID: observation.ID,
				Source: observation.Source, CollectionRunID: observation.CollectionRunID,
				Stage: observation.Stage, ReferenceRun: referenceRunID != "" && observation.CollectionRunID == referenceRunID,
				ObservedAt: observation.ObservedAt,
			})
		}
	}

	keys := make([]surfaceKey, 0, len(surfaces))
	for key := range surfaces {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].target != keys[j].target {
			return keys[i].target < keys[j].target
		}
		return keys[i].port < keys[j].port
	})

	results := make([]ServiceSurface, 0, len(keys))
	for _, key := range keys {
		surface := surfaces[key]
		surface.TCPStates = sortedUnique(surface.TCPStates)
		surface.EvidenceIDs = mapKeys(evidenceIDs[key])
		surface.ObservationIDs = mapKeys(observationIDs[key])
		sort.Slice(surface.HTTP, func(i, j int) bool { return surface.HTTP[i].EvidenceID < surface.HTTP[j].EvidenceID })
		sort.Slice(surface.TLS, func(i, j int) bool { return surface.TLS[i].EvidenceID < surface.TLS[j].EvidenceID })
		sort.Slice(surface.ObservationRefs, func(i, j int) bool {
			if !surface.ObservationRefs[i].ObservedAt.Equal(surface.ObservationRefs[j].ObservedAt) {
				return surface.ObservationRefs[i].ObservedAt.Before(surface.ObservationRefs[j].ObservedAt)
			}
			return surface.ObservationRefs[i].ObservationID < surface.ObservationRefs[j].ObservationID
		})

		if len(surface.TCPStates) > 0 {
			surface.Protocols = append(surface.Protocols, "TCP")
		}
		if len(surface.HTTP) > 0 {
			surface.Protocols = append(surface.Protocols, "HTTP")
		}
		if len(surface.TLS) > 0 {
			surface.Protocols = append(surface.Protocols, "TLS")
		}

		parts := []string{fmt.Sprintf("%s:%d", surface.Target, surface.Port)}
		if len(surface.TCPStates) > 0 {
			parts = append(parts, "TCP "+strings.Join(surface.TCPStates, "/"))
		}
		for _, http := range surface.HTTP {
			parts = append(parts, fmt.Sprintf("%s %d", strings.ToUpper(http.Scheme), http.StatusCode))
		}
		for _, tls := range surface.TLS {
			parts = append(parts, "TLS "+tls.TLSVersion)
		}
		hasReferenceRun, hasHistoricalRun, hasLegacyRun := false, false, false
		for _, observation := range surface.ObservationRefs {
			switch {
			case observation.CollectionRunID == "":
				hasLegacyRun = true
			case referenceRunID != "" && observation.CollectionRunID == referenceRunID:
				hasReferenceRun = true
			default:
				hasHistoricalRun = true
			}
		}
		switch {
		case hasReferenceRun && (hasHistoricalRun || hasLegacyRun):
			surface.TemporalScope = "REFERENCE_AND_HISTORICAL"
		case hasReferenceRun:
			surface.TemporalScope = "REFERENCE_RUN_ONLY"
		case hasHistoricalRun && hasLegacyRun:
			surface.TemporalScope = "HISTORICAL_AND_LEGACY"
		case hasHistoricalRun:
			surface.TemporalScope = "HISTORICAL_ONLY"
		case hasLegacyRun:
			surface.TemporalScope = "LEGACY_TIME_ONLY"
		default:
			surface.TemporalScope = "NO_OBSERVATION_PROVENANCE"
		}
		parts = append(parts, "Temporal scope "+surface.TemporalScope)
		surface.Summary = strings.Join(parts, " | ")
		surface.Limitations = []string{
			"Temporal scope is classified using explicit collection-run IDs where available; legacy observations without run IDs cannot be assigned confidently to a run.",
			"Records are grouped by exact normalized target and port; collection timestamps may differ.",
			"A shared endpoint key does not prove the same process, backend, tenant, or infrastructure owner.",
			"An observed HTTP response or TLS certificate does not by itself establish a vulnerability or secure configuration.",
		}
		switch surface.TemporalScope {
		case "HISTORICAL_ONLY":
			surface.Limitations = append(surface.Limitations, "No service observation for this endpoint was recorded in the reference collection run; this surface is historical context, not a current-run confirmation.")
		case "REFERENCE_AND_HISTORICAL":
			surface.Limitations = append(surface.Limitations, "This surface combines reference-run and historical observations; compare each observation's run ID and timestamp before treating the layers as simultaneous.")
		case "LEGACY_TIME_ONLY":
			surface.Limitations = append(surface.Limitations, "Legacy observations lack explicit collection-run IDs; temporal grouping relies on timestamps and may be ambiguous.")
		}
		if len(surface.TCPStates) > 1 {
			surface.Limitations = append(surface.Limitations, "Multiple TCP states were observed across records; compare timestamps before treating them as a state change or contradiction.")
		}
		if len(surface.HTTP) > 0 {
			surface.NextSteps = append(surface.NextSteps, "Review HTTP status, final URL, redirects, content type, and server metadata; validate unexpected behavior with a bounded authorized follow-up.")
		}
		if len(surface.TLS) > 0 {
			surface.NextSteps = append(surface.NextSteps, "Review certificate identity, SAN coverage, issuer, validity period, fingerprint, negotiated TLS version, and verification result.")
		}
		if len(surface.TCPStates) > 0 && containsString(surface.TCPStates, "OPEN") && len(surface.HTTP) == 0 && len(surface.TLS) == 0 {
			surface.NextSteps = append(surface.NextSteps, "Identify the application protocol on this open TCP port using authorized, bounded service identification.")
		}
		if len(surface.TCPStates) == 0 {
			surface.Limitations = append(surface.Limitations, "No separate TCP state observation is present for this port in the selected evidence set; application-layer evidence remains valid on its own.")
		}
		if err := surface.Validate(); err != nil {
			return nil, fmt.Errorf("validate service surface %q: %w", surface.ID, err)
		}
		results = append(results, *surface)
	}
	return results, nil
}

func (s ServiceSurface) Validate() error {
	if strings.TrimSpace(s.ID) == "" || normalizeFindingTarget(s.Target) == "" || s.Port < 1 || s.Port > 65535 {
		return fmt.Errorf("service surface identity, target, and port are required")
	}
	if len(s.EvidenceIDs) == 0 || len(s.Protocols) == 0 || strings.TrimSpace(s.Summary) == "" {
		return fmt.Errorf("service surface requires evidence, protocols, and summary")
	}
	for _, id := range s.EvidenceIDs {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("service surface contains empty evidence ID")
		}
	}
	for _, id := range s.ObservationIDs {
		if strings.TrimSpace(id) == "" {
			return fmt.Errorf("service surface contains empty observation ID")
		}
	}
	for _, limitation := range s.Limitations {
		if strings.TrimSpace(limitation) == "" {
			return fmt.Errorf("service surface contains empty limitation")
		}
	}
	return nil
}

// GenerateServiceHypotheses creates a conservative, testable hypothesis only
// when HTTPS and a certificate observation share the same target and port.
func GenerateServiceHypotheses(surfaces []ServiceSurface) ([]Hypothesis, error) {
	results := make([]Hypothesis, 0)
	for _, surface := range surfaces {
		if err := surface.Validate(); err != nil {
			return nil, fmt.Errorf("invalid service surface: %w", err)
		}
		var https []ServiceHTTPObservation
		for _, observation := range surface.HTTP {
			if strings.EqualFold(observation.Scheme, "https") {
				https = append(https, observation)
			}
		}
		if len(https) == 0 || len(surface.TLS) == 0 {
			continue
		}
		if !serviceEvidenceObservedTogether(surface, https, surface.TLS) {
			continue
		}

		supportingIDs := append([]string(nil), surface.EvidenceIDs...)
		supportingFacts := []string{
			fmt.Sprintf("An HTTPS response (status %d) was observed at %s:%d.", https[0].StatusCode, surface.Target, surface.Port),
			fmt.Sprintf("A TLS certificate (%s) was separately observed at the same normalized target and port.", surface.TLS[0].Fingerprint),
		}
		if containsString(surface.TCPStates, "OPEN") {
			supportingFacts = append(supportingFacts, "A TCP OPEN observation was recorded for the same target and port.")
		}
		verification := []string{
			"Compare the source and timestamps of the HTTPS and certificate observations; repeat collection close together to test whether the endpoint remains consistent.",
			"Check certificate SANs, hostname matching, validity, chain verification, and SNI behavior for the exact requested hostname.",
			"Compare the HTTP response and TLS certificate across repeated observations to identify load balancing, certificate rotation, or proxy termination.",
		}
		hypothesis := Hypothesis{
			ID:              "hypothesis:service-https:" + surface.Target + ":" + fmt.Sprint(surface.Port),
			Title:           "HTTPS and TLS observations align on one endpoint",
			Statement:       fmt.Sprintf("An HTTPS response and a TLS certificate were observed for %s:%d. This is consistent with the endpoint presenting TLS for the observed HTTPS service; it does not identify the backend application.", surface.Target, surface.Port),
			Confidence:      HypothesisConfidenceLow,
			SupportingIDs:   sortedUnique(supportingIDs),
			SupportingFacts: supportingFacts,
			Alternative:     "A reverse proxy, load balancer, shared TLS terminator, SNI-based routing, or certificate rotation may explain the observations without identifying a single backend process.",
			Limitations:     "This is a low-confidence endpoint-level interpretation only. Matching target and port do not prove a shared backend, origin server, application process, tenant, or infrastructure owner. A reverse proxy, load balancer, shared TLS terminator, or changing network path may produce these observations. Collection timestamps may differ, and this is not evidence of a vulnerability.",
			Verification:    verification,
		}
		if err := hypothesis.Validate(); err != nil {
			return nil, fmt.Errorf("validate service hypothesis for %s:%d: %w", surface.Target, surface.Port, err)
		}
		results = append(results, hypothesis)
	}
	sort.Slice(results, func(i, j int) bool { return results[i].ID < results[j].ID })
	return results, nil
}

func serviceEvidenceObservedTogether(surface ServiceSurface, httpObservations []ServiceHTTPObservation, tlsObservations []ServiceTLSObservation) bool {
	refsByEvidence := make(map[string][]ServiceObservationRef)
	for _, ref := range surface.ObservationRefs {
		refsByEvidence[ref.EvidenceID] = append(refsByEvidence[ref.EvidenceID], ref)
	}
	const legacyMaxSkew = 5 * time.Minute
	for _, httpObservation := range httpObservations {
		for _, tlsObservation := range tlsObservations {
			for _, httpRef := range refsByEvidence[httpObservation.EvidenceID] {
				for _, tlsRef := range refsByEvidence[tlsObservation.EvidenceID] {
					if httpRef.CollectionRunID != "" && httpRef.CollectionRunID == tlsRef.CollectionRunID {
						return true
					}
					if httpRef.CollectionRunID != "" || tlsRef.CollectionRunID != "" {
						continue
					}
					skew := httpRef.ObservedAt.Sub(tlsRef.ObservedAt)
					if skew < 0 {
						skew = -skew
					}
					if skew <= legacyMaxSkew {
						return true
					}
				}
			}
		}
	}
	return false
}

func serviceTargetInScope(entity, target string) bool {
	if entity == target {
		return true
	}
	if net.ParseIP(target) != nil {
		return false
	}
	return strings.HasSuffix(entity, "."+target)
}

func sortedUnique(values []string) []string {
	sort.Strings(values)
	result := make([]string, 0, len(values))
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}

func mapKeys(values map[string]struct{}) []string {
	result := make([]string, 0, len(values))
	for value := range values {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
