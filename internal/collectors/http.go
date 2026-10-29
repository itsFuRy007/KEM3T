package collectors

import (
	"context"
	"crypto/tls"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/itsFuRy007/kem3t/internal/events"
)

const (
	defaultHTTPTimeout = 8 * time.Second
	maxHTTPBodyBytes   = 1 << 20
	maxHTTPRedirects   = 5
)

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// HTTP performs a bounded HTTP(S) request to an explicitly supplied target.
// It records response metadata, never stores the response body, and does not
// interpret headers as proof of software identity or vulnerability.
type HTTP struct {
	Target  string
	Scheme  string
	Port    int
	Timeout time.Duration
}

// Run emits one event when an HTTP response is obtained. In auto mode an
// unschemed host is tried over HTTPS first, then HTTP if HTTPS fails.
func (c *HTTP) Run(ctx context.Context, output chan<- events.Event) error {
	if ctx == nil {
		return fmt.Errorf("context is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	target := strings.TrimSpace(c.Target)
	if target == "" {
		return fmt.Errorf("HTTP target is required")
	}
	if c.Port < 0 || c.Port > 65535 {
		return fmt.Errorf("HTTP port must be between 0 and 65535")
	}
	scheme := strings.ToLower(strings.TrimSpace(c.Scheme))
	if scheme == "" {
		scheme = "auto"
	}
	if scheme != "auto" && scheme != "http" && scheme != "https" {
		return fmt.Errorf("HTTP scheme must be auto, http, or https")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}

	var supplied *url.URL
	if strings.Contains(target, "://") {
		parsed, err := url.ParseRequestURI(target)
		if err != nil || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			return fmt.Errorf("target must be a hostname, IP address, or absolute HTTP(S) URL")
		}
		if parsed.User != nil {
			return fmt.Errorf("credentials in target URLs are not allowed")
		}
		supplied = parsed
	} else {
		if strings.ContainsAny(target, "/?#@") {
			return fmt.Errorf("target must be a hostname, IP address, or absolute HTTP(S) URL")
		}
		parsed, err := url.Parse("//" + target)
		if err != nil || parsed.Hostname() == "" || parsed.User != nil {
			return fmt.Errorf("invalid HTTP target %q", target)
		}
		supplied = parsed
	}
	host := strings.TrimSuffix(strings.ToLower(supplied.Hostname()), ".")
	if net.ParseIP(host) == nil {
		if host == "" || strings.Contains(host, " ") {
			return fmt.Errorf("invalid HTTP hostname")
		}
	}
	schemes := []string{scheme}
	if scheme == "auto" {
		if supplied.Scheme == "http" || supplied.Scheme == "https" {
			schemes = []string{supplied.Scheme}
		} else {
			schemes = []string{"https", "http"}
		}
	}
	var lastErr error
	for _, currentScheme := range schemes {
		event, err := c.observe(ctx, supplied, host, currentScheme, timeout)
		if err != nil {
			lastErr = err
			continue
		}
		select {
		case output <- event:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no HTTP scheme attempted")
	}
	return fmt.Errorf("HTTP collection failed for %q: %w", target, lastErr)
}

func (c *HTTP) observe(parent context.Context, supplied *url.URL, host, scheme string, timeout time.Duration) (events.Event, error) {
	requestURL := *supplied
	requestURL.Scheme = scheme
	if requestURL.Path == "" {
		requestURL.Path = "/"
	}
	if c.Port > 0 {
		requestURL.Host = net.JoinHostPort(host, strconv.Itoa(c.Port))
	} else if supplied.Port() == "" {
		port := 80
		if scheme == "https" {
			port = 443
		}
		requestURL.Host = net.JoinHostPort(host, strconv.Itoa(port))
	} else {
		requestURL.Host = supplied.Host
	}
	port, err := strconv.Atoi(requestURL.Port())
	if requestURL.Port() == "" {
		if scheme == "https" { port = 443 } else { port = 80 }
	} else if err != nil || port < 1 || port > 65535 {
		return events.Event{}, fmt.Errorf("invalid HTTP URL port")
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	redirectCount := 0
	transport := &http.Transport{
		Proxy: nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return fmt.Errorf("redirect to unsupported scheme")
			}
			if !strings.EqualFold(req.URL.Hostname(), requestURL.Hostname()) {
				return fmt.Errorf("cross-host redirect rejected to preserve target scope")
			}
			if len(via) > maxHTTPRedirects {
				return http.ErrUseLastResponse
			}
			redirectCount++
			return nil
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, requestURL.String(), nil)
	if err != nil {
		return events.Event{}, fmt.Errorf("build HTTP request: %w", err)
	}
	req.Header.Set("User-Agent", "KEM3T/1.0 (+authorized infrastructure research)")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8")
	resp, err := client.Do(req)
	if err != nil {
		return events.Event{}, fmt.Errorf("request %s: %w", requestURL.Redacted(), err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPBodyBytes+1))
	if err != nil {
		return events.Event{}, fmt.Errorf("read bounded HTTP response: %w", err)
	}
	truncated := len(body) > maxHTTPBodyBytes
	if truncated {
		body = body[:maxHTTPBodyBytes]
	}
	title := ""
	if match := titlePattern.FindSubmatch(body); len(match) == 2 {
		title = strings.Join(strings.Fields(string(match[1])), " ")
		if len(title) > 512 { title = title[:512] }
	}
	tlsVersion, tlsVerified := "", false
	if resp.TLS != nil {
		tlsVersion = tlsVersionLabel(resp.TLS.Version)
		tlsVerified = len(resp.TLS.VerifiedChains) > 0
	}
	finalURL := resp.Request.URL.String()
	location := strings.TrimSpace(resp.Header.Get("Location"))
	if location != "" && len(location) > 2048 { location = location[:2048] }
	data := map[string]string{
		"scheme": scheme, "port": strconv.Itoa(port), "url": requestURL.String(),
		"final_url": finalURL, "status_code": strconv.Itoa(resp.StatusCode),
		"content_type": boundedHeader(resp.Header.Get("Content-Type")),
		"server": boundedHeader(resp.Header.Get("Server")),
		"powered_by": boundedHeader(resp.Header.Get("X-Powered-By")),
		"title": title, "location": location,
		"redirect_count": strconv.Itoa(redirectCount),
		"body_truncated": strconv.FormatBool(truncated),
		"tls_version": tlsVersion, "tls_verified": strconv.FormatBool(tlsVerified),
	}
	now := time.Now().UTC()
	return events.Event{
		ID: fmt.Sprintf("http-%d-%x", now.UnixNano(), hashPrefix(requestURL.String())),
		Type: events.EventHTTPObserved, Timestamp: now, Target: host,
		Source: "http-collector", Data: data,
	}, nil
}

func boundedHeader(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > 512 { return value[:512] }
	return value
}

func tlsVersionLabel(version uint16) string {
	switch version {
	case tls.VersionTLS12: return "TLS 1.2"
	case tls.VersionTLS13: return "TLS 1.3"
	default: return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

func hashPrefix(value string) []byte {
	// Kept local to the collector so event IDs remain compact and non-secret.
	sum := sha256.Sum256([]byte(value))
	return sum[:6]
}
