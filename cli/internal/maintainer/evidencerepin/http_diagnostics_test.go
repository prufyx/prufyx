// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

type diagnosticTransport func(*http.Request) (*http.Response, error)

func (f diagnosticTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func diagnosticClient(t *testing.T, server *httptest.Server) *http.Client {
	t.Helper()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: nil}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{Transport: diagnosticTransport(func(r *http.Request) (*http.Response, error) {
		request := r.Clone(r.Context())
		request.URL.Scheme, request.URL.Host = u.Scheme, u.Host
		return transport.RoundTrip(request)
	})}
}

func TestHTTPRefusalDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		header http.Header
		want   string
	}{
		{"primary", 403, http.Header{"X-Ratelimit-Remaining": {"0"}, "X-Ratelimit-Reset": {"1800000000"}}, "status=403 remaining=0 reset_epoch=1800000000 retry_after=UNKNOWN"},
		{"retry", 403, http.Header{"Retry-After": {"00120"}}, "status=403 remaining=UNKNOWN reset_epoch=UNKNOWN retry_after=120"},
		{"permission-like", 403, nil, "status=403 remaining=UNKNOWN reset_epoch=UNKNOWN retry_after=UNKNOWN"},
		{"too-many", 429, http.Header{"Retry-After": {"Sun, 22 Nov 2026 20:00:00 GMT"}}, "status=429 remaining=UNKNOWN reset_epoch=UNKNOWN retry_after=2026-11-22T20:00:00Z"},
		{"other", 500, nil, ""},
		{"success", 200, nil, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "Bearer request-marker" {
					t.Error("request authentication wiring changed")
				}
				for name, values := range tc.header {
					w.Header()[name] = values
				}
				w.Header().Set("Set-Cookie", "cookie-marker")
				w.Header().Set("Authorization", "response-marker")
				w.Header().Set("X-Unrelated", "unrelated-marker")
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, "body-marker")
			}))
			defer server.Close()
			client := diagnosticClient(t, server)
			var stderr bytes.Buffer
			fetcher := GitHubAPIFetcher{Token: "request-marker", OnRefusal: NewHTTPRefusalReporter(&stderr)}
			body, status, err := fetcher.fetch(context.Background(), "/path-marker?query-marker", client)
			if err != nil || status != tc.status || string(body) != "body-marker" {
				t.Fatalf("fetch result changed: %q %d %v", body, status, err)
			}
			want := ""
			if tc.want != "" {
				want = "evidence repin: http_refusal transport=api " + tc.want + "\n"
			}
			if stderr.String() != want || stderr.Len() > 256 {
				t.Fatalf("diagnostic = %q, want %q", stderr.String(), want)
			}
			for _, marker := range []string{"request-marker", "cookie-marker", "response-marker", "unrelated-marker", "body-marker", "path-marker", "query-marker", server.URL, "api.github.com"} {
				if strings.Contains(stderr.String(), marker) {
					t.Errorf("diagnostic disclosed %q", marker)
				}
			}
		})
	}
}

func TestHTTPRefusalNormalizedHeaders(t *testing.T) {
	for _, values := range [][]string{nil, {""}, {"0", "1"}, {"-1"}, {"+1"}, {"1e3"}, {" 1"}, {"marker"}, {"1\t"}, {"\x01marker"}, {"é"}, {strings.Repeat("1", 65)}, {"18446744073709551616"}} {
		h := http.Header{"X-Ratelimit-Remaining": values, "X-Ratelimit-Reset": values, "Retry-After": values}
		d := parseHTTPRefusal(403, h)
		if d.remaining != "UNKNOWN" || d.reset != "UNKNOWN" || d.retryAfter != "UNKNOWN" {
			t.Errorf("normalized header %q accepted: %+v", values, d)
		}
	}
	for _, tc := range []struct{ name, value, want string }{
		{"X-RateLimit-Remaining", strings.Repeat("0", 63) + "1", "1"},
		{"X-RateLimit-Remaining", "1000000000", "1000000000"},
		{"X-RateLimit-Remaining", "1000000001", "UNKNOWN"},
		{"X-RateLimit-Reset", "4102444800", "4102444800"},
		{"X-RateLimit-Reset", "4102444801", "UNKNOWN"},
		{"Retry-After", "604800", "604800"},
		{"Retry-After", "604801", "UNKNOWN"},
		{"Retry-After", "Fri, 01 Jan 1999 00:00:00 GMT", "UNKNOWN"},
		{"Retry-After", "Sat, 01 Jan 2101 00:00:00 GMT", "UNKNOWN"},
	} {
		h := http.Header{}
		h.Set(tc.name, tc.value)
		d := parseHTTPRefusal(429, h)
		got := map[string]string{"X-RateLimit-Remaining": d.remaining, "X-RateLimit-Reset": d.reset, "Retry-After": d.retryAfter}[tc.name]
		if got != tc.want {
			t.Errorf("%s=%q: %q, want %q", tc.name, tc.value, got, tc.want)
		}
	}
}

type diagnosticAPI struct {
	fetcher GitHubAPIFetcher
	client  *http.Client
}

func (f diagnosticAPI) Fetch(ctx context.Context, path string) ([]byte, int, error) {
	return f.fetcher.fetch(ctx, path, f.client)
}

func TestHTTPRefusalWorklistAndStopUnchanged(t *testing.T) {
	for _, status := range []int{403, 429} {
		for _, bodyMode := range []string{"complete", "truncated", "oversized"} {
			t.Run(http.StatusText(status)+"/"+bodyMode, func(t *testing.T) {
				var later atomic.Int64
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if !strings.Contains(r.URL.Path, "owner1") {
						later.Add(1)
						w.WriteHeader(404)
						return
					}
					if bodyMode == "truncated" {
						w.Header().Set("Content-Length", "20")
					}
					w.WriteHeader(status)
					if bodyMode == "oversized" {
						_, _ = io.CopyN(w, strings.NewReader(strings.Repeat("x", int(maxAPIBytes)+1)), maxAPIBytes+1)
					} else {
						_, _ = io.WriteString(w, "x")
					}
				}))
				defer server.Close()
				client := diagnosticClient(t, server)
				citations := []Citation{
					{RulePack: "p", RuleID: "r1", Project: "a", SourceID: "s1", Owner: "owner1", Repo: "repo1", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1},
					{RulePack: "p", RuleID: "r2", Project: "a", SourceID: "s2", Owner: "owner2", Repo: "repo2", Path: "x", OldCommit: commitA, OldDigest: "sha256:x", StartLine: 1, EndLine: 1},
				}
				var prior Worklist
				var priorState *State
				for _, enabled := range []bool{false, true} {
					later.Store(0)
					var stderr bytes.Buffer
					fetcher := GitHubAPIFetcher{}
					if enabled {
						fetcher.OnRefusal = NewHTTPRefusalReporter(&stderr)
					}
					state := newState()
					worklist, err := BuildWorklist(context.Background(), citations, nil, 0, state, diagnosticAPI{fetcher, client}, fakeBlobFetcher{}, fixedNow(), DefaultMaxAge, nil)
					if err != nil {
						t.Fatal(err)
					}
					if (later.Load() == 0) != (bodyMode == "complete") {
						t.Fatalf("body %s: later requests=%d", bodyMode, later.Load())
					}
					wantStatus := repoPendingError
					if bodyMode == "complete" {
						wantStatus = repoPendingRateLimited
					}
					if state.Repos["owner1/repo1"].Status != wantStatus {
						t.Fatalf("body %s: status=%s", bodyMode, state.Repos["owner1/repo1"].Status)
					}
					if enabled {
						if !reflect.DeepEqual(prior, worklist) || !reflect.DeepEqual(priorState, state) {
							t.Fatal("diagnostics changed worklist or persisted state")
						}
						if strings.Count(stderr.String(), "http_refusal") != 1 {
							t.Fatalf("missing or repeated diagnostic: %q", stderr.String())
						}
					} else {
						prior, priorState = worklist, state
					}
				}
			})
		}
	}
}

type diagnosticFailedBody struct{}

func (diagnosticFailedBody) Read([]byte) (int, error) { return 0, io.ErrClosedPipe }
func (diagnosticFailedBody) Close() error             { return nil }

func TestHTTPRefusalFailedBodyUnchanged(t *testing.T) {
	for _, status := range []int{403, 429} {
		var stderr bytes.Buffer
		client := &http.Client{Transport: diagnosticTransport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: status, Header: http.Header{}, Body: diagnosticFailedBody{}}, nil
		})}
		fetcher := GitHubAPIFetcher{OnRefusal: NewHTTPRefusalReporter(&stderr)}
		body, gotStatus, err := fetcher.fetch(context.Background(), "/", client)
		if body != nil || gotStatus != 0 || !errors.Is(err, errRejected) || stderr.Len() == 0 {
			t.Fatalf("failed body changed: %q %d %v diagnostic=%q", body, gotStatus, err, stderr.String())
		}
	}
}

func TestHTTPRefusalReporterOnce(t *testing.T) {
	var stderr bytes.Buffer
	report := NewHTTPRefusalReporter(&stderr)
	d := parseHTTPRefusal(403, http.Header{})
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() { report(d) })
	}
	wg.Wait()
	if strings.Count(stderr.String(), "\n") != 1 || stderr.Len() > 256 {
		t.Fatalf("not once-only/bounded: %q", stderr.String())
	}
	if NewHTTPRefusalReporter(nil) != nil {
		t.Fatal("nil writer must preserve disabled reporting")
	}
	report = NewHTTPRefusalReporter(diagnosticFailedWriter{})
	report(d)
}

type diagnosticFailedWriter struct{}

func (diagnosticFailedWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }
