package externalintel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestDoExternalRequestRetriesTransientStatus(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method=%s, want GET", r.Method)
		}
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			http.Error(w, "temporary", http.StatusServiceUnavailable)
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := doExternalRequest(context.Background(), server.Client(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("calls=%d, want 2", got)
	}
}

func TestDoExternalRequestDoesNotRetryPermanentClientError(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "bad request", http.StatusBadRequest)
	}))
	defer server.Close()
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := doExternalRequest(context.Background(), server.Client(), req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := calls.Load(); got != 1 {
		t.Fatalf("calls=%d, want 1", got)
	}
}

func TestDoExternalRequestCancellationInterruptsRetryWait(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "10")
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	done := make(chan error, 1)
	go func() {
		_, err := doExternalRequest(ctx, server.Client(), req)
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected cancellation error")
		}
	case <-time.After(time.Second):
		t.Fatal("request retry wait did not honor cancellation")
	}
}

func TestRetryDelayHonorsAndCapsRetryAfter(t *testing.T) {
	if got := retryDelay(0, "2"); got != 2*time.Second {
		t.Fatalf("got %v, want 2s", got)
	}
	if got := retryDelay(0, "999"); got != externalMaxRetryDelay {
		t.Fatalf("got %v, want capped delay", got)
	}
	if got := retryDelay(0, "invalid"); got <= 0 {
		t.Fatalf("expected fallback delay, got %v", got)
	}
}

func TestDoExternalRequestRejectsHTTPSDowngradeWithCustomClient(t *testing.T) {
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHits.Add(1)
		fmt.Fprint(w, "should not be reached")
	}))
	defer plain.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/redirected", http.StatusFound)
	}))
	defer secure.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, secure.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	_, err = doExternalRequest(ctx, secure.Client(), req)
	if err == nil || !strings.Contains(err.Error(), "HTTPS redirect cannot downgrade") {
		t.Fatalf("expected HTTPS downgrade to be rejected, got %v", err)
	}
	if got := plainHits.Load(); got != 0 {
		t.Fatalf("plain HTTP redirect target received %d requests", got)
	}
}

func TestRetryDelayCapsOversizedNumericRetryAfter(t *testing.T) {
	if got := retryDelay(0, "999999999999999999999999999999999999"); got != externalMaxRetryDelay {
		t.Fatalf("got %v, want capped delay %v", got, externalMaxRetryDelay)
	}
}


func TestAuthenticatedProviderRedirectCannotLeakAPIKeyAcrossHosts(t *testing.T) {
	var received atomic.Int32
	destination := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-OTX-API-KEY") != "" {
			received.Add(1)
		}
		fmt.Fprint(w, "unexpected destination request")
	}))
	defer destination.Close()

	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, destination.URL, http.StatusFound)
	}))
	defer origin.Close()

	endpoint, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, origin.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-OTX-API-KEY", "test-secret")

	client := sameHostHTTPSClient(origin.Client(), endpoint)
	_, err = doExternalRequest(context.Background(), client, req)
	if !errors.Is(err, errExternalRedirectPolicy) {
		t.Fatalf("expected cross-host redirect rejection, got %v", err)
	}
	if got := received.Load(); got != 0 {
		t.Fatalf("destination received API key %d times", got)
	}
}
