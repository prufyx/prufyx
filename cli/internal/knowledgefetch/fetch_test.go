// SPDX-License-Identifier: AGPL-3.0-only

package knowledgefetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestValidateSourceRejectsInvalidInputBeforeNetwork(t *testing.T) {
	var calls atomic.Int32
	client := &http.Client{Transport: roundTripper(func(*http.Request) (*http.Response, error) { calls.Add(1); return nil, errors.New("must not dial") })}
	for _, source := range []string{
		"", "https://:443/package", "https://example.test/" + strings.Repeat("x", 4096), "http://example.test/package", "/relative", "https:opaque", "https://user:pass@example.test/package",
		"https://example.test/package?", "https://example.test/package?canary=private", "https://example.test/package#", "https://example.test/package#fragment",
		"https://example.test/a%20b", "https://example.test/a b", "https://example.test/a\n", "https://example.test/a\x00b",
	} {
		t.Run(strconv.Quote(source), func(t *testing.T) {
			if err := ValidateSource(source); !errors.Is(err, ErrInvalidSource) {
				t.Fatalf("ValidateSource(%q) = %v", source, err)
			}
			_, err := fetchWithClient(context.Background(), source, client)
			if !errors.Is(err, ErrInvalidSource) || strings.Contains(err.Error(), "canary") || (source != "" && strings.Contains(err.Error(), source)) {
				t.Fatalf("Fetch(%q) = %v", source, err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("invalid source attempted network access")
	}
}

func TestFetchFixedTranscriptAndCompleteBytes(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.Header.Get("Accept") != "application/octet-stream" || r.Header.Get("Accept-Encoding") != "identity" || r.Header.Get("User-Agent") != "prufyx-knowledge-fetch/1" {
			t.Errorf("unexpected transcript: method=%q headers=%v", r.Method, r.Header)
		}
		if r.RequestURI != "/knowledge.tar" || len(r.Header) != 4 || r.Header.Get("Connection") != "close" || r.ContentLength != 0 {
			t.Errorf("unexpected path, body or additional headers: %s %v %d", r.RequestURI, r.Header, r.ContentLength)
		}
		_, _ = w.Write([]byte("complete-package"))
	}))
	defer server.Close()
	client := testTLSClient(server)
	got, err := fetchWithClient(context.Background(), server.URL+"/knowledge.tar", client)
	if err != nil || string(got) != "complete-package" || calls.Load() != 1 {
		t.Fatalf("Fetch = %q, %v, calls=%d", got, err, calls.Load())
	}
}

func TestFetchNeverFollowsRedirect(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { targetCalls.Add(1) }))
	defer target.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/target", http.StatusFound)
	}))
	defer origin.Close()
	client := testTLSClient(origin)
	_, err := fetchWithClient(context.Background(), origin.URL+"/package", client)
	if !errors.Is(err, ErrTransfer) || targetCalls.Load() != 0 {
		t.Fatalf("redirect result=%v targetCalls=%d", err, targetCalls.Load())
	}
}

func TestFetchIgnoresEnvironmentProxy(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = w.Write([]byte("ok")) }))
	defer server.Close()
	client := testTLSClient(server)
	if client.Transport.(*http.Transport).Proxy != nil || client.Jar != nil {
		t.Fatal("transport consults proxy or cookie state")
	}
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	got, err := fetchWithClient(context.Background(), server.URL+"/package", client)
	if err != nil || string(got) != "ok" || calls.Load() != 1 {
		t.Fatalf("proxy affected transfer: bytes=%q err=%v calls=%d", got, err, calls.Load())
	}
}

func TestFetchRejectsResponseBoundaryFailures(t *testing.T) {
	tooLarge := strconv.Itoa(maxPackageBytes + 1)
	for name, handler := range map[string]http.HandlerFunc{
		"non-200": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusTeapot)
			_, _ = w.Write([]byte("server-secret-canary"))
		},
		"encoding": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write([]byte("x"))
		},
		"declared-oversize": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Length", tooLarge)
			w.WriteHeader(http.StatusOK)
		},
		"streaming-oversize": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(make([]byte, maxPackageBytes+1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewTLSServer(handler)
			defer server.Close()
			client := testTLSClient(server)
			_, err := fetchWithClient(context.Background(), server.URL+"/package", client)
			if name == "declared-oversize" || name == "streaming-oversize" {
				if !errors.Is(err, ErrOversized) {
					t.Fatalf("Fetch error = %v", err)
				}
			} else if !errors.Is(err, ErrTransfer) {
				t.Fatalf("Fetch error = %v", err)
			}
			if strings.Contains(err.Error(), "server-secret-canary") || strings.Contains(err.Error(), server.URL) {
				t.Fatalf("untrusted server data leaked through error: %v", err)
			}
		})
	}
}

func TestFetchConvertsTruncatedReadAndCancellationToTransfer(t *testing.T) {
	client := &http.Client{Transport: roundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: readCloser{Reader: errReader{}}}, nil
	})}
	_, err := fetchWithClient(context.Background(), "https://example.test/package", client)
	if !errors.Is(err, ErrTransfer) {
		t.Fatalf("truncated Fetch error = %v", err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("cancelled request reached server") }))
	defer server.Close()
	client = testTLSClient(server)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = fetchWithClient(ctx, server.URL+"/package", client)
	if !errors.Is(err, ErrTransfer) {
		t.Fatalf("cancelled Fetch error = %v", err)
	}
}

func testTLSClient(server *httptest.Server) *http.Client {
	config := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	return newClient(config)
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type readCloser struct{ io.Reader }

func (readCloser) Close() error { return nil }
