package collectors

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"github.com/itsFuRy007/kem3t/internal/events"
	"math/big"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

func makeTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(12345),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse generated test certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        cert,
	}
}
func TestParseTLSCertificate(t *testing.T) {
	pair := makeTestCertificate(t)
	cert := pair.Leaf
	got, err := ParseTLSCertificate(cert)
	if err != nil {
		t.Fatalf("ParseTLSCertificate() error = %v", err)
	}
	if got.SHA256Fingerprint == "" || len(got.SHA256Fingerprint) != 64 {
		t.Fatalf("unexpected SHA-256 fingerprint: %q", got.SHA256Fingerprint)
	}
	if _, err := hex.DecodeString(got.SHA256Fingerprint); err != nil {
		t.Fatalf("fingerprint is not hexadecimal: %v", err)
	}
	if got.Subject == "" || got.Issuer == "" {
		t.Fatalf("subject and issuer should be populated: %+v", got)
	}
	if len(got.DNSNames) != 1 || got.DNSNames[0] != "localhost" {
		t.Fatalf("unexpected DNS SANs: %v", got.DNSNames)
	}
	if len(got.IPAddresses) != 1 || got.IPAddresses[0] != "127.0.0.1" {
		t.Fatalf("unexpected IP SANs: %v", got.IPAddresses)
	}
	if got.NotBefore.IsZero() || got.NotAfter.IsZero() {
		t.Fatal("certificate validity dates should be populated")
	}
	if got.SerialNumber != "12345" {
		t.Fatalf("unexpected serial number: %q", got.SerialNumber)
	}
}
func TestParseTLSCertificateRejectsNil(t *testing.T) {
	if _, err := ParseTLSCertificate(nil); err == nil {
		t.Fatal("expected an error for a nil certificate")
	}
}
func TestTLSCollectorEmitsCertificateEvent(t *testing.T) {
	certificate := makeTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	server := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	defer server.Close()
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		conn, acceptErr := server.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		if tlsConn, ok := conn.(*tls.Conn); ok {
			_ = tlsConn.Handshake()
		}
	}()
	defer func() {
		_ = server.Close()
		select {
		case <-serverDone:
		case <-time.After(time.Second):
		}
	}()
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split listener address: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("parse listener port: %v", err)
	}
	output := make(chan events.Event, 1)
	collector := &TLS{
		Target:  "localhost",
		Port:    port,
		Timeout: 3 * time.Second,
	}
	if err := collector.Run(context.Background(), output); err != nil {
		t.Fatalf("TLS.Run() error = %v", err)
	}
	select {
	case event := <-output:
		if event.Type != events.EventTLSCertificateFound {
			t.Fatalf("unexpected event type: %s", event.Type)
		}
		if event.Target != "localhost" {
			t.Fatalf("unexpected event target: %q", event.Target)
		}
		if event.Data["sha256_fingerprint"] == "" {
			t.Fatal("fingerprint is missing")
		}
		if event.Data["tls_version"] == "" {
			t.Fatal("TLS version is missing")
		}
		if event.Data["verified"] != "false" {
			t.Fatalf("self-signed test certificate should not be marked verified: %q", event.Data["verified"])
		}
	case <-time.After(4 * time.Second):
		t.Fatal("timed out waiting for TLS event")
	}
}
func TestTLSCollectorRejectsURL(t *testing.T) {
	output := make(chan events.Event, 1)
	err := (&TLS{Target: "https://localhost"}).Run(context.Background(), output)
	if err == nil || !strings.Contains(err.Error(), "not a URL") {
		t.Fatalf("expected URL validation error, got %v", err)
	}
}
func TestTLSCollectorRejectsInvalidPort(t *testing.T) {
	output := make(chan events.Event, 1)
	err := (&TLS{Target: "localhost", Port: 70000}).Run(context.Background(), output)
	if err == nil {
		t.Fatal("expected invalid port error")
	}
}


func TestTLSCollectorRejectsNilContext(t *testing.T) {
	collector := &TLS{Target: "localhost"}
	if err := collector.Run(nil, make(chan events.Event, 1)); err == nil {
		t.Fatal("Run() should reject a nil context")
	}
}
