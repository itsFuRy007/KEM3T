package collectors

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

func TestHTTPCollectsResponseMetadataAndBoundsBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "test-server")
		w.Header().Set("X-Powered-By", "test-framework")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("<html><title>  Test   Page </title><body>ok</body></html>"))
	}))
	defer server.Close()

	out := make(chan events.Event, 1)
	c := &HTTP{Target: server.URL, Scheme: "auto", Timeout: time.Second}
	if err := c.Run(context.Background(), out); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	event := <-out
	if event.Type != events.EventHTTPObserved {
		t.Fatalf("event type = %s", event.Type)
	}
	if event.Data["status_code"] != "201" {
		t.Fatalf("status = %q", event.Data["status_code"])
	}
	if event.Data["title"] != "Test Page" {
		t.Fatalf("title = %q", event.Data["title"])
	}
	if event.Data["server"] != "test-server" {
		t.Fatalf("server = %q", event.Data["server"])
	}
	if event.Data["powered_by"] != "test-framework" {
		t.Fatalf("powered_by = %q", event.Data["powered_by"])
	}
	if event.Data["scheme"] != "http" {
		t.Fatalf("scheme = %q", event.Data["scheme"])
	}
	if event.Data["body_truncated"] != "false" {
		t.Fatalf("truncated = %q", event.Data["body_truncated"])
	}
}

func TestHTTPFollowsRedirectAndRecordsFinalURL(t *testing.T) {
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	defer server.Close()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/final", http.StatusFound)
	})
	mux.HandleFunc("/final", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	out := make(chan events.Event, 1)
	c := &HTTP{Target: server.URL + "/start", Scheme: "auto", Timeout: time.Second}
	if err := c.Run(context.Background(), out); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	event := <-out
	if event.Data["redirect_count"] != "1" {
		t.Fatalf("redirect_count = %q", event.Data["redirect_count"])
	}
	if !strings.HasSuffix(event.Data["final_url"], "/final") {
		t.Fatalf("final_url = %q", event.Data["final_url"])
	}
	if event.Data["status_code"] != "204" {
		t.Fatalf("status = %q", event.Data["status_code"])
	}
}

func TestHTTPRejectsInvalidInput(t *testing.T) {
	tests := []struct {
		name      string
		collector HTTP
	}{
		{name: "empty target", collector: HTTP{Scheme: "auto"}},
		{name: "invalid scheme", collector: HTTP{Target: "example.com", Scheme: "ftp"}},
		{name: "invalid port", collector: HTTP{Target: "example.com", Scheme: "http", Port: 65536}},
		{name: "URL credentials", collector: HTTP{Target: "http://user:pass@example.com", Scheme: "auto"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.collector.Run(context.Background(), make(chan events.Event, 1)); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestHTTPHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := (&HTTP{Target: "127.0.0.1", Scheme: "http"}).Run(ctx, make(chan events.Event, 1))
	if err == nil {
		t.Fatal("expected context cancellation")
	}
}

func TestHTTPMarksBoundedBodyAsTruncated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", maxHTTPBodyBytes+32)))
	}))
	defer server.Close()
	out := make(chan events.Event, 1)
	if err := (&HTTP{Target: server.URL, Scheme: "auto", Timeout: 3 * time.Second}).Run(context.Background(), out); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	event := <-out
	if event.Data["body_truncated"] != "true" {
		t.Fatalf("body_truncated = %q, want true", event.Data["body_truncated"])
	}
}

func TestHTTPRejectsCrossHostRedirect(t *testing.T) {
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, strings.Replace(other.URL, "127.0.0.1", "localhost", 1), http.StatusFound)
	}))
	defer server.Close()
	out := make(chan events.Event, 1)
	err := (&HTTP{Target: server.URL, Scheme: "auto", Timeout: time.Second}).Run(context.Background(), out)
	if err == nil {
		t.Fatal("expected cross-host redirect to be rejected")
	}
}
