package externalintel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// External providers are shared across KEM3T collection modes. A host-keyed
// gate prevents concurrent modes from independently overwhelming one provider.
const (
	externalMinRequestInterval = 150 * time.Millisecond
	externalMaxAttempts        = 4
	externalMaxRedirects       = 4
	externalMaxRetryDelay      = 10 * time.Second
)

var errExternalRedirectPolicy = errors.New("external redirect rejected by policy")

var providerGate = struct {
	sync.Mutex
	next map[string]time.Time
}{next: make(map[string]time.Time)}

func waitForProvider(ctx context.Context, host string) error {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return fmt.Errorf("external provider host is required")
	}
	now := time.Now()
	providerGate.Lock()
	next := providerGate.next[host]
	start := now
	if next.After(start) {
		start = next
	}
	providerGate.next[host] = start.Add(externalMinRequestInterval)
	providerGate.Unlock()

	delay := time.Until(start)
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// doExternalRequest serializes request starts per provider host and retries only
// idempotent GET requests after transient transport failures or 429/5xx responses.
// Retry responses are drained (bounded) and closed before waiting. Retry-After
// is honored but capped, and every wait is cancellation-aware.
func doExternalRequest(ctx context.Context, client *http.Client, req *http.Request) (*http.Response, error) {
	if ctx == nil {
		return nil, fmt.Errorf("context is required")
	}
	if req == nil || req.URL == nil {
		return nil, fmt.Errorf("request URL is required")
	}
	if req.Method != http.MethodGet {
		return nil, fmt.Errorf("provider retry policy only permits GET requests")
	}
	if client == nil {
		client = http.DefaultClient
	}
	safeClient := *client
	previousCheckRedirect := safeClient.CheckRedirect
	safeClient.CheckRedirect = func(redirect *http.Request, via []*http.Request) error {
		if redirect.URL.User != nil {
			return fmt.Errorf("%w: credentials in redirect URL are not allowed", errExternalRedirectPolicy)
		}
		if len(via) > 0 && strings.EqualFold(via[len(via)-1].URL.Scheme, "https") &&
			!strings.EqualFold(redirect.URL.Scheme, "https") {
			return fmt.Errorf("%w: HTTPS redirect cannot downgrade to %q", errExternalRedirectPolicy, redirect.URL.Scheme)
		}
		if len(via) >= externalMaxRedirects {
			return fmt.Errorf("%w: too many redirects", errExternalRedirectPolicy)
		}
		if previousCheckRedirect != nil {
			if err := previousCheckRedirect(redirect, via); err != nil {
				if errors.Is(err, http.ErrUseLastResponse) {
					return err
				}
				return fmt.Errorf("%w: %v", errExternalRedirectPolicy, err)
			}
		}
		return nil
	}
	host := req.URL.Host
	var lastErr error
	for attempt := 0; attempt < externalMaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := waitForProvider(ctx, host); err != nil {
			return nil, err
		}
		attemptReq := req.Clone(ctx)
		resp, err := safeClient.Do(attemptReq)
		if err != nil {
			if errors.Is(err, errExternalRedirectPolicy) {
				return nil, err
			}
			lastErr = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if attempt == externalMaxAttempts-1 {
				break
			}
			if err := waitRetry(ctx, retryDelay(attempt, "")); err != nil {
				return nil, err
			}
			continue
		}
		if !retryableProviderStatus(resp.StatusCode) || attempt == externalMaxAttempts-1 {
			return resp, nil
		}
		delay := retryDelay(attempt, resp.Header.Get("Retry-After"))
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		_ = resp.Body.Close()
		if err := waitRetry(ctx, delay); err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("provider request failed after %d attempts: %w", externalMaxAttempts, lastErr)
}

func retryableProviderStatus(status int) bool {
	return status == http.StatusTooManyRequests ||
		status == http.StatusBadGateway ||
		status == http.StatusServiceUnavailable ||
		status == http.StatusGatewayTimeout
}

func retryDelay(attempt int, retryAfter string) time.Duration {
	if value := strings.TrimSpace(retryAfter); value != "" {
		if strings.Trim(value, "0123456789") == "" {
			seconds, err := strconv.ParseUint(value, 10, 64)
			if err != nil || seconds > uint64(externalMaxRetryDelay/time.Second) {
				return externalMaxRetryDelay
			}
			return time.Duration(seconds) * time.Second
		}
		if when, err := http.ParseTime(value); err == nil {
			delay := time.Until(when)
			if delay < 0 {
				return 0
			}
			if delay > externalMaxRetryDelay {
				return externalMaxRetryDelay
			}
			return delay
		}
	}
	delay := 250 * time.Millisecond * time.Duration(1<<attempt)
	if delay > externalMaxRetryDelay {
		return externalMaxRetryDelay
	}
	return delay
}

func waitRetry(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return ctx.Err()
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
