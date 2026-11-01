package pipeline

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/graph"
	"github.com/itsFuRy007/kem3t/internal/observations"
)

func makePipelineTestCertificate(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(12345),
		Subject:               pkix.Name{CommonName: "127.0.0.1"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(
		rand.Reader,
		template,
		template,
		&key.PublicKey,
		key,
	)
	if err != nil {
		t.Fatalf("create test certificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
	}
}

func TestRunTLSPersistsEvidenceAndBuildsNormalizedService(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	server := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{makePipelineTestCertificate(t)},
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
		case <-time.After(2 * time.Second):
			t.Error("TLS test server did not stop")
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	result, err := RunTLS(
		context.Background(),
		"127.0.0.1",
		port,
		t.TempDir(),
	)
	if err != nil {
		t.Fatalf("RunTLS() error: %v", err)
	}
	if result.Event == nil {
		t.Fatal("expected a TLS certificate event")
	}
	if result.Report.Target != "127.0.0.1" || result.Report.ReferenceRunID == "" {
		t.Fatalf("TLS adapter did not return the shared intelligence report: %+v", result.Report)
	}
	if result.Evidence.ID == "" {
		t.Fatal("expected TLS evidence")
	}
	if result.Observation.EvidenceID != result.Evidence.ID {
		t.Fatal("TLS observation does not reference its evidence")
	}
	if len(result.Normalized.Rejected) != 0 {
		t.Fatalf("unexpected normalization rejections: %#v", result.Normalized.Rejected)
	}
	if len(result.Normalized.Observations) != 1 {
		t.Fatalf(
			"normalized observations = %d, want 1",
			len(result.Normalized.Observations),
		)
	}
	observation := result.Normalized.Observations[0]
	if observation.Kind != observations.KindTLSCertificate {
		t.Fatalf("observation kind = %q, want %q",
			observation.Kind, observations.KindTLSCertificate)
	}
	if observation.Target != "127.0.0.1" || observation.Port != port {
		t.Fatalf("unexpected normalized endpoint: %#v", observation)
	}
	if observation.Value == "" {
		t.Fatal("normalized TLS fingerprint is empty")
	}
	if len(observation.EvidenceIDs) != 1 ||
		observation.EvidenceIDs[0] != result.Evidence.ID {
		t.Fatalf("normalized observation has incorrect evidence references: %#v",
			observation.EvidenceIDs)
	}
	if len(result.Normalized.Services) != 1 {
		t.Fatalf("normalized services = %d, want 1",
			len(result.Normalized.Services))
	}
	service := result.Normalized.Services[0]
	if service.Target != "127.0.0.1" || service.Port != port {
		t.Fatalf("unexpected normalized service endpoint: %#v", service)
	}
	if service.Application != "" {
		t.Fatalf("TLS certificate alone must not infer an application: %q",
			service.Application)
	}
	if service.Indicators["tls_observed"] != "true" {
		t.Fatalf("TLS indicator missing: %#v", service.Indicators)
	}
	if service.Indicators["tls_certificate_sha256"] != observation.Value {
		t.Fatal("service fingerprint does not match normalized observation")
	}
	if len(service.EvidenceIDs) != 1 ||
		service.EvidenceIDs[0] != result.Evidence.ID {
		t.Fatalf("service has incorrect evidence references: %#v",
			service.EvidenceIDs)
	}
	if err := result.Graph.Validate(); err != nil {
		t.Fatalf("graph validation failed: %v", err)
	}
	foundServiceNode := false
	foundServiceEdge := false
	foundCertificateEdge := false
	for _, node := range result.Graph.Nodes {
		if node.Type == graph.NodeNetworkService &&
			node.ID == service.ID {
			foundServiceNode = true
		}
	}
	for _, edge := range result.Graph.Edges {
		switch edge.Type {
		case graph.EdgeHostsService:
			if edge.Port == port &&
				containsTestID(edge.EvidenceIDs, result.Evidence.ID) {
				foundServiceEdge = true
			}
		case graph.EdgePresentsCertificate:
			if edge.Port == port &&
				containsTestID(edge.EvidenceIDs, result.Evidence.ID) {
				foundCertificateEdge = true
			}
		}
	}
	if !foundServiceNode {
		t.Fatal("graph is missing the normalized network service node")
	}
	if !foundServiceEdge {
		t.Fatal("graph is missing the evidence-backed service relationship")
	}
	if !foundCertificateEdge {
		t.Fatal("graph is missing the evidence-backed certificate relationship")
	}
}

func containsTestID(ids []string, want string) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}

func TestRunTLSRejectsInvalidInput(t *testing.T) {
	if _, err := RunTLS(nil, "127.0.0.1", 443, t.TempDir()); err == nil {
		t.Fatal("expected nil context error")
	}
	if _, err := RunTLS(context.Background(), "127.0.0.1", 70000, t.TempDir()); err == nil {
		t.Fatal("expected invalid port error")
	}
	if _, err := RunTLS(context.Background(), " ", 443, t.TempDir()); err == nil {
		t.Fatal("expected empty target error")
	}
}
