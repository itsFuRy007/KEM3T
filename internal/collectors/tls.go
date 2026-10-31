package collectors

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/itsFuRy007/kem3t/internal/events"
	"net"
	"strconv"
	"strings"
	"time"
)

// TLSCertificate contains normalized metadata extracted from a server certificate.
type TLSCertificate struct {
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
	VerificationError  string    `json:"verification_error,omitempty"`
}

// ParseTLSCertificate extracts useful metadata from an X.509 certificate.
func ParseTLSCertificate(cert *x509.Certificate) (TLSCertificate, error) {
	if cert == nil {
		return TLSCertificate{}, fmt.Errorf("certificate is required")
	}
	fingerprint := sha256.Sum256(cert.Raw)
	dnsNames := append([]string(nil), cert.DNSNames...)
	ipAddresses := make([]string, 0, len(cert.IPAddresses))
	for _, ip := range cert.IPAddresses {
		ipAddresses = append(ipAddresses, ip.String())
	}
	return TLSCertificate{
		Subject:            cert.Subject.String(),
		Issuer:             cert.Issuer.String(),
		SerialNumber:       cert.SerialNumber.String(),
		DNSNames:           dnsNames,
		IPAddresses:        ipAddresses,
		NotBefore:          cert.NotBefore.UTC(),
		NotAfter:           cert.NotAfter.UTC(),
		SHA256Fingerprint:  hex.EncodeToString(fingerprint[:]),
		SignatureAlgorithm: cert.SignatureAlgorithm.String(),
		PublicKeyAlgorithm: cert.PublicKeyAlgorithm.String(),
	}, nil
}

// TLS collects the leaf certificate presented by a TLS server.
// Certificate extraction is deliberately separate from trust validation:
// Verified is true only when Go successfully verifies the peer certificate.
// The collector does not treat an unverified certificate as trusted.
type TLS struct {
	Target  string
	Port    int
	Timeout time.Duration
}

// Run connects to the configured TLS endpoint and emits its leaf certificate.
func (c *TLS) Run(ctx context.Context, output chan<- events.Event) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	target := strings.TrimSpace(c.Target)
	if target == "" {
		return fmt.Errorf("TLS target is required")
	}
	if strings.Contains(target, "://") || strings.ContainsAny(target, "/?#") {
		return fmt.Errorf("TLS target must be a hostname or IP address, not a URL")
	}
	port := c.Port
	if port == 0 {
		port = 443
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("TLS port must be between 1 and 65535")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	host := target
	if parsedHost, parsedPort, err := net.SplitHostPort(target); err == nil {
		host = parsedHost
		if c.Port == 0 {
			parsed, parseErr := strconv.Atoi(parsedPort)
			if parseErr != nil || parsed < 1 || parsed > 65535 {
				return fmt.Errorf("invalid port in TLS target %q", target)
			}
			port = parsed
		}
	} else if strings.HasPrefix(target, "[") || strings.HasSuffix(target, "]") {
		return fmt.Errorf("invalid bracketed TLS target %q", target)
	}
	if host == "" {
		return fmt.Errorf("TLS hostname is required")
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	address := net.JoinHostPort(host, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: timeout}
	rawConn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("connect to TLS endpoint %q: %w", address, err)
	}
	defer rawConn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		if err := rawConn.SetDeadline(deadline); err != nil {
			return fmt.Errorf("set TLS connection deadline: %w", err)
		}
	}
	config := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, // Extraction only; trust is not implied.
	}
	conn := tls.Client(rawConn, config)
	if err := conn.HandshakeContext(ctx); err != nil {
		return fmt.Errorf("TLS handshake with %q: %w", address, err)
	}
	defer conn.Close()
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("TLS endpoint %q did not present a certificate", address)
	}
	result, err := ParseTLSCertificate(state.PeerCertificates[0])
	if err != nil {
		return fmt.Errorf("parse TLS certificate: %w", err)
	}
	result.Target = host
	result.Port = port
	result.TLSVersion = tlsVersionName(state.Version)
	verificationErr := verifyTLSCertificate(state, host)
	result.Verified = verificationErr == nil
	if verificationErr != nil {
		result.VerificationError = verificationErr.Error()
	}
	dnsNamesJSON, err := json.Marshal(result.DNSNames)
	if err != nil {
		return fmt.Errorf("encode certificate DNS names: %w", err)
	}
	ipAddressesJSON, err := json.Marshal(result.IPAddresses)
	if err != nil {
		return fmt.Errorf("encode certificate IP addresses: %w", err)
	}
	event := events.Event{
		ID:        fmt.Sprintf("tls-%d-%s", time.Now().UTC().UnixNano(), result.SHA256Fingerprint[:12]),
		Type:      events.EventTLSCertificateFound,
		Timestamp: time.Now().UTC(),
		Target:    host,
		Source:    "tls-collector",
		Data: map[string]string{
			"port":                 strconv.Itoa(port),
			"subject":              result.Subject,
			"issuer":               result.Issuer,
			"serial_number":        result.SerialNumber,
			"dns_names":            string(dnsNamesJSON),
			"ip_addresses":         string(ipAddressesJSON),
			"not_before":           result.NotBefore.Format(time.RFC3339),
			"not_after":            result.NotAfter.Format(time.RFC3339),
			"sha256_fingerprint":   result.SHA256Fingerprint,
			"signature_algorithm":  result.SignatureAlgorithm,
			"public_key_algorithm": result.PublicKeyAlgorithm,
			"tls_version":          result.TLSVersion,
			"verified":             strconv.FormatBool(result.Verified),
			"verification_error":   result.VerificationError,
		},
	}
	if err := event.Validate(); err != nil {
		return fmt.Errorf("validate TLS event: %w", err)
	}
	select {
	case output <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// verifyTLSCertificate checks the peer certificate against the system
// trust store and verifies that it is valid for the requested server name.
func verifyTLSCertificate(state tls.ConnectionState, host string) error {
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("peer did not present a certificate")
	}

	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}

	_, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		DNSName:       host,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	return err
}

func tlsVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}
