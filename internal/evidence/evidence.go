package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// Type identifies the kind of fact supported by an observation.
type Type string

const (
	TypeDNSAddress     Type = "DNS_ADDRESS"
	TypeTLSCertificate Type = "TLS_CERTIFICATE"
	TypeTCPPort        Type = "TCP_PORT"
	TypeHTTPService    Type = "HTTP_SERVICE"
	TypeCTDNSName      Type = "CT_DNS_NAME"
	TypeRDAPRegistration Type = "RDAP_REGISTRATION"
	TypeASNOrigin Type = "ASN_ORIGIN"
	TypePassiveDNS Type = "PASSIVE_DNS"
	TypeThreatIntel Type = "THREAT_INTEL"
)

// TLSCertificateDetails contains the certificate metadata stored in evidence.
type TLSCertificateDetails struct {
	Target             string    `json:"target"`
	Port               int       `json:"port"`
	Subject            string    `json:"subject"`
	Issuer             string    `json:"issuer"`
	SerialNumber       string    `json:"serial_number"`
	DNSNames           []string  `json:"dns_names"`
	IPAddresses        []string  `json:"ip_addresses"`
	NotBefore          time.Time `json:"not_before"`
	NotAfter           time.Time `json:"not_after"`
	SHA256Fingerprint  string    `json:"sha256_fingerprint"`
	SignatureAlgorithm string    `json:"signature_algorithm"`
	PublicKeyAlgorithm string    `json:"public_key_algorithm"`
	TLSVersion         string    `json:"tls_version"`
	Verified           bool      `json:"verified"`
}

// CTDNSNameDetails records a domain name observed in a CT certificate entry.
// It records a source observation, not proof of current hosting or ownership.
type CTDNSNameDetails struct {
	Target       string    `json:"target"`
	DNSName      string    `json:"dns_name"`
	CertificateID int      `json:"certificate_id"`
	IssuerName   string    `json:"issuer_name,omitempty"`
	NotBefore    string    `json:"not_before,omitempty"`
	NotAfter     string    `json:"not_after,omitempty"`
	Source       string    `json:"source"`
	RetrievedAt  time.Time `json:"retrieved_at"`
}

// RDAPRegistrationDetails stores minimized public registration metadata.
type RDAPRegistrationEvent struct {
 Action string `json:"action"`
 Date string `json:"date"`
}

type RDAPRegistrationDetails struct {
 Target string `json:"target"`
 Handle string `json:"handle,omitempty"`
 Registrar string `json:"registrar,omitempty"`
 Status []string `json:"status"`
 NameServers []string `json:"name_servers"`
 Events []RDAPRegistrationEvent `json:"events"`
}

type ThreatPulseDetails struct {
 ID string `json:"id"`
 Name string `json:"name"`
 Tags []string `json:"tags"`
 Created string `json:"created,omitempty"`
 Modified string `json:"modified,omitempty"`
}
type ThreatIntelDetails struct {
 Target string `json:"target"`
 IndicatorType string `json:"indicator_type"`
 Source string `json:"source"`
 PulseCount int `json:"pulse_count"`
 Pulses []ThreatPulseDetails `json:"pulses"`
 Truncated bool `json:"truncated"`
}

type PassiveDNSDetails struct {
 Target string `json:"target"`
 Hostname string `json:"hostname"`
 Address string `json:"address"`
 RecordType string `json:"record_type"`
 FirstSeen string `json:"first_seen,omitempty"`
 LastSeen string `json:"last_seen,omitempty"`
 ASN string `json:"asn,omitempty"`
 Source string `json:"source"`
}

type ASNOriginRecord struct {
 ASN uint32 `json:"asn"`
 Prefix string `json:"prefix"`
 Country string `json:"country,omitempty"`
 Registry string `json:"registry,omitempty"`
 Allocated string `json:"allocated,omitempty"`
 NetworkName string `json:"network_name,omitempty"`
 MappingSource string `json:"mapping_source"`
 RDAPSource string `json:"rdap_source"`
}
type ASNOriginDetails struct {
 Target string `json:"target"`
 Records []ASNOriginRecord `json:"records"`
}

// TCPPortDetails contains metadata for a discovered TCP port.
type TCPPortDetails struct {
	Target   string `json:"target"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	State    string `json:"state"`
}

// HTTPServiceDetails records a bounded HTTP response observation.
type HTTPServiceDetails struct {
	Target        string `json:"target"`
	Scheme        string `json:"scheme"`
	Port          int    `json:"port"`
	URL           string `json:"url"`
	FinalURL      string `json:"final_url"`
	StatusCode    int    `json:"status_code"`
	ContentType   string `json:"content_type"`
	Server        string `json:"server"`
	PoweredBy     string `json:"powered_by"`
	Title         string `json:"title"`
	RedirectCount int    `json:"redirect_count"`
	BodyTruncated bool   `json:"body_truncated"`
	TLSVersion    string `json:"tls_version,omitempty"`
	TLSVerified   bool   `json:"tls_verified"`
}

// Evidence represents a normalized fact about an entity.
// It does not store individual observation timestamps or event references.
type Evidence struct {
	ID       string `json:"id"`
	EntityID string `json:"entity_id"`
	Type     Type   `json:"type"`
	Value    string `json:"value"`
}

// Validate checks whether the evidence has the required fields and valid content.
func (e Evidence) Validate() error {
	if strings.TrimSpace(e.ID) == "" {
		return errors.New("evidence ID is required")
	}

	if strings.TrimSpace(e.EntityID) == "" {
		return errors.New("evidence entity ID is required")
	}

	if strings.TrimSpace(e.Value) == "" {
		return errors.New("evidence value is required")
	}

	switch e.Type {
	case TypeDNSAddress:
		if !IsValidDomain(e.EntityID) {
			return errors.New("DNS evidence entity ID must be a valid domain")
		}
		if net.ParseIP(strings.TrimSpace(e.Value)) == nil {
			return errors.New("DNS address evidence must contain a valid IP address")
		}
		return nil

	case TypeTLSCertificate:
		return validateTLSCertificateEvidence(e)

	case TypeTCPPort:
		return validateTCPPortEvidence(e)

	case TypeHTTPService:
		return validateHTTPServiceEvidence(e)

	case TypeCTDNSName:
		return validateCTDNSNameEvidence(e)

	case TypeRDAPRegistration:
		return validateRDAPRegistrationEvidence(e)

	case TypeASNOrigin:
		return validateASNOriginEvidence(e)

	case TypePassiveDNS:
		return validatePassiveDNSEvidence(e)

	case TypeThreatIntel:
		return validateThreatIntelEvidence(e)

	default:
		return errors.New("evidence type is invalid")
	}
}

func validateTLSCertificateEvidence(e Evidence) error {
	target := strings.TrimSpace(e.EntityID)
	if !IsValidDomain(target) && net.ParseIP(target) == nil {
		return errors.New("TLS evidence entity ID must be a valid domain or IP address")
	}

	var details TLSCertificateDetails
	if err := json.Unmarshal([]byte(e.Value), &details); err != nil {
		return fmt.Errorf("TLS certificate evidence value must be valid JSON: %w", err)
	}

	if strings.TrimSpace(details.Target) == "" {
		return errors.New("TLS certificate target is required")
	}

	normalizedTarget := strings.TrimSuffix(
		strings.ToLower(strings.TrimSpace(details.Target)), ".",
	)
	normalizedEntity := strings.TrimSuffix(strings.ToLower(target), ".")
	if normalizedTarget != normalizedEntity {
		return errors.New("TLS certificate target must match evidence entity ID")
	}

	if details.Port < 1 || details.Port > 65535 {
		return errors.New("TLS certificate port must be between 1 and 65535")
	}

	fingerprint := strings.TrimSpace(details.SHA256Fingerprint)
	if len(fingerprint) != sha256.Size*2 {
		return errors.New("TLS certificate SHA-256 fingerprint must contain 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(fingerprint); err != nil {
		return errors.New("TLS certificate SHA-256 fingerprint must be hexadecimal")
	}

	if details.NotBefore.IsZero() || details.NotAfter.IsZero() {
		return errors.New("TLS certificate validity timestamps are required")
	}
	if details.NotAfter.Before(details.NotBefore) {
		return errors.New("TLS certificate expiry must not precede its start date")
	}

	if strings.TrimSpace(details.TLSVersion) == "" {
		return errors.New("TLS certificate protocol version is required")
	}

	return nil
}

func validateTCPPortEvidence(e Evidence) error {
	target := strings.TrimSpace(e.EntityID)
	if !IsValidDomain(target) && net.ParseIP(target) == nil {
		return errors.New("TCP port evidence entity ID must be a valid domain or IP address")
	}

	var details TCPPortDetails
	if err := json.Unmarshal([]byte(e.Value), &details); err != nil {
		return fmt.Errorf("TCP port evidence value must be valid JSON: %w", err)
	}

	normalizedTarget := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(details.Target)), ".")
	normalizedEntity := strings.TrimSuffix(strings.ToLower(target), ".")
	if normalizedTarget == "" || normalizedTarget != normalizedEntity {
		return errors.New("TCP port target must match evidence entity ID")
	}
	if strings.ToLower(strings.TrimSpace(details.Protocol)) != "tcp" {
		return errors.New("TCP port protocol must be tcp")
	}
	if details.Port < 1 || details.Port > 65535 {
		return errors.New("TCP port must be between 1 and 65535")
	}
	if strings.ToLower(strings.TrimSpace(details.State)) != "open" {
		return errors.New("TCP port state must be open")
	}
	return nil
}

func validateHTTPServiceEvidence(e Evidence) error {
 target := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(e.EntityID)), ".")
 if !IsValidDomain(target) && net.ParseIP(target) == nil { return errors.New("HTTP evidence entity ID must be a valid domain or IP address") }
 var d HTTPServiceDetails
 if err := json.Unmarshal([]byte(e.Value), &d); err != nil { return fmt.Errorf("HTTP service evidence value must be valid JSON: %w", err) }
 if strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d.Target)), ".") != target { return errors.New("HTTP service target must match evidence entity ID") }
 if d.Scheme != "http" && d.Scheme != "https" { return errors.New("HTTP service scheme must be http or https") }
 if d.Port < 1 || d.Port > 65535 { return errors.New("HTTP service port must be between 1 and 65535") }
 if d.StatusCode < 100 || d.StatusCode > 599 { return errors.New("HTTP status code must be between 100 and 599") }
 for label, raw := range map[string]string{"url": d.URL, "final URL": d.FinalURL} { u, err := url.Parse(strings.TrimSpace(raw)); if err != nil || u == nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") { return fmt.Errorf("HTTP service %s must be an absolute HTTP(S) URL", label) } }
 if d.RedirectCount < 0 { return errors.New("HTTP redirect count cannot be negative") }
 return nil
}

func validateCTDNSNameEvidence(e Evidence) error {
	target := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(e.EntityID)), ".")
	if !IsValidDomain(target) { return errors.New("CT evidence entity ID must be a valid domain") }
	var d CTDNSNameDetails
	if err := json.Unmarshal([]byte(e.Value), &d); err != nil { return fmt.Errorf("CT evidence value must be valid JSON: %w", err) }
	if d.Target != target { return errors.New("CT evidence target must match evidence entity ID") }
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d.DNSName)), ".")
	if !IsValidDomain(name) || name != d.DNSName { return errors.New("CT DNS name must be valid and normalized") }
	if name != target && !strings.HasSuffix(name, "."+target) { return errors.New("CT DNS name must be within the requested domain scope") }
	if d.CertificateID < 0 { return errors.New("CT certificate ID cannot be negative") }
	if strings.TrimSpace(d.Source) == "" { return errors.New("CT source is required") }
	if d.RetrievedAt.IsZero() { return errors.New("CT retrieval timestamp is required") }
	return nil
}

func validateRDAPRegistrationEvidence(e Evidence) error {
 target := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(e.EntityID)), ".")
 if !IsValidDomain(target) { return errors.New("RDAP evidence entity ID must be a valid domain") }
 var d RDAPRegistrationDetails
 if err := json.Unmarshal([]byte(e.Value), &d); err != nil { return fmt.Errorf("RDAP evidence value must be valid JSON: %w", err) }
 if d.Target != target { return errors.New("RDAP target must match evidence entity ID") }
 for _, ns := range d.NameServers {
  normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(ns)), ".")
  if !IsValidDomain(normalized) || normalized != ns { return fmt.Errorf("RDAP nameserver %q is invalid or not normalized", ns) }
 }
 return nil
}

func validateASNOriginEvidence(e Evidence) error {
 target:=net.ParseIP(strings.TrimSpace(e.EntityID))
 if target==nil{return errors.New("ASN evidence entity ID must be an IP address")}
 var d ASNOriginDetails
 if err:=json.Unmarshal([]byte(e.Value),&d);err!=nil{return fmt.Errorf("ASN evidence value must be valid JSON: %w",err)}
 if net.ParseIP(d.Target)==nil||net.ParseIP(d.Target).String()!=target.String(){return errors.New("ASN target must match evidence entity ID")}
 if len(d.Records)==0{return errors.New("ASN evidence must contain at least one origin record")}
 for _,record:=range d.Records{
  if record.ASN==0{return errors.New("origin ASN must be positive")}
  _,prefix,err:=net.ParseCIDR(record.Prefix);if err!=nil||!prefix.Contains(target){return fmt.Errorf("ASN prefix %q does not contain target IP",record.Prefix)}
  if strings.TrimSpace(record.MappingSource)==""||strings.TrimSpace(record.RDAPSource)==""{return errors.New("ASN mapping and RDAP source attribution are required")}
 }
 return nil
}

func validatePassiveDNSEvidence(e Evidence)error{
 target:=strings.TrimSuffix(strings.ToLower(strings.TrimSpace(e.EntityID)),".")
 if !IsValidDomain(target){return errors.New("passive-DNS evidence entity ID must be a valid domain")}
 var d PassiveDNSDetails
 if err:=json.Unmarshal([]byte(e.Value),&d);err!=nil{return fmt.Errorf("passive-DNS evidence value must be valid JSON: %w",err)}
 if d.Target!=target{return errors.New("passive-DNS target must match evidence entity ID")}
 hostname:=strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d.Hostname)),".")
 if !IsValidDomain(hostname)||hostname!=d.Hostname||(hostname!=target&&!strings.HasSuffix(hostname,"."+target)){return errors.New("passive-DNS hostname must be normalized and within target scope")}
 ip:=net.ParseIP(d.Address);if ip==nil||ip.String()!=d.Address{return errors.New("passive-DNS address must be a normalized IP")}
 if d.RecordType=="A"&&ip.To4()==nil||d.RecordType=="AAAA"&&ip.To4()!=nil||(d.RecordType!="A"&&d.RecordType!="AAAA"){return errors.New("passive-DNS record type must match address family")}
 if strings.TrimSpace(d.Source)==""{return errors.New("passive-DNS source is required")}
 return nil
}

func validateThreatIntelEvidence(e Evidence)error{
 target:=strings.TrimSpace(e.EntityID)
 ip:=net.ParseIP(target)
 if ip!=nil{if ip.String()!=target{return errors.New("threat-intelligence IP target must be normalized")}}else{target=strings.TrimSuffix(strings.ToLower(target),".");if !IsValidDomain(target){return errors.New("threat-intelligence entity ID must be a domain or IP")}}
 var d ThreatIntelDetails
 if err:=json.Unmarshal([]byte(e.Value),&d);err!=nil{return fmt.Errorf("threat-intelligence evidence value must be valid JSON: %w",err)}
 if d.Target!=target{return errors.New("threat-intelligence target must match evidence entity ID")}
 if strings.TrimSpace(d.Source)==""||strings.TrimSpace(d.IndicatorType)==""{return errors.New("threat-intelligence source and indicator type are required")}
 if d.PulseCount<0{return errors.New("threat pulse count cannot be negative")}
 seen:=map[string]struct{}{}
 for _,pulse:=range d.Pulses{if strings.TrimSpace(pulse.ID)==""||strings.TrimSpace(pulse.Name)==""{return errors.New("threat pulse ID and name are required")};if _,ok:=seen[pulse.ID];ok{return errors.New("duplicate threat pulse ID")};seen[pulse.ID]=struct{}{}}
 return nil
}
