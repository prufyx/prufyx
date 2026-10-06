// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestGitHubSourceGetBoundsAndRedirects(t *testing.T) {
	var otherHits atomic.Int32
	var otherAuth atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		otherAuth.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte("elsewhere"))
	}))
	defer other.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("fine")) })
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", 5000)))
	})
	mux.HandleFunc("/cross", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/x", http.StatusFound)
	})
	mux.HandleFunc("/same", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ok", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tests := []struct {
		name    string
		path    string
		limit   int64
		want    string
		wantErr string
	}{
		{"ok", "/ok", 100, "fine", ""},
		{"same host redirect", "/same", 100, "fine", ""},
		{"oversized body", "/big", 100, "", "exceeds"},
		{"cross host redirect", "/cross", 100, "", "redirect"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			otherHits.Store(0)
			g := &GitHubSource{Token: "tok-secret"}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			body, _, err := g.get(ctx, srv.URL+tc.path, true, tc.limit)
			if tc.wantErr == "" {
				if err != nil || string(body) != tc.want {
					t.Fatalf("got %q, %v; want %q", body, err, tc.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v; want containing %q", err, tc.wantErr)
			}
			if otherHits.Load() != 0 {
				t.Fatalf("the redirect target on another host was contacted")
			}
		})
	}
}

func TestGitHubSourceRejectsPlainHTTPAndIgnoresProxyEnv(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		_, _ = w.Write([]byte("via-proxy"))
	}))
	defer proxy.Close()
	for _, k := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy"} {
		t.Setenv(k, proxy.URL)
	}
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	for _, u := range []string{
		"http://api.github.com.example.test/repos/a/b",
		"ftp://api.github.com/repos/a/b",
		"file:///etc/passwd",
	} {
		t.Run(u, func(t *testing.T) {
			g := &GitHubSource{Token: "tok-secret"}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if body, _, err := g.get(ctx, u, true, 100); err == nil {
				t.Fatalf("fetched %q, want refusal", body)
			}
		})
	}
	if proxyHits.Load() != 0 {
		t.Fatalf("the environment proxy was contacted %d times", proxyHits.Load())
	}
}

func TestGitHubSourceTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	old := httpTimeout
	httpTimeout = 100 * time.Millisecond
	defer func() { httpTimeout = old }()

	for _, name := range []string{"default client", "caller client without timeout"} {
		t.Run(name, func(t *testing.T) {
			g := &GitHubSource{}
			if name != "default client" {
				g.Client = &http.Client{}
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			start := time.Now()
			if _, _, err := g.get(ctx, srv.URL, true, 100); err == nil {
				t.Fatal("stalled server fetched without error")
			}
			if time.Since(start) > 8*time.Second {
				t.Fatalf("fetch took %v", time.Since(start))
			}
		})
	}
}

func TestHTTPRedirectPolicyAndURLCheck(t *testing.T) {
	check := newHTTPClient(nil).CheckRedirect
	mk := func(u string) *http.Request { r, _ := http.NewRequest(http.MethodGet, u, nil); return r }
	first := []*http.Request{mk("https://api.github.com/a")}
	tests := []struct {
		name string
		to   string
		via  []*http.Request
		ok   bool
	}{
		{"same host", "https://api.github.com/b", first, true},
		{"other host", "https://evil.example/b", first, false},
		{"downgrade", "http://api.github.com/b", first, false},
		{"too many", "https://api.github.com/b", append(append(first, first...), append(first, first...)...), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := check(mk(tc.to), tc.via); (err == nil) != tc.ok {
				t.Fatalf("err = %v, ok want %v", err, tc.ok)
			}
		})
	}
	for u, ok := range map[string]bool{
		"https://api.github.com/x": true, "http://127.0.0.1:1/x": true, "http://[::1]:1/x": true,
		"http://api.github.com/x": false, "http://localhost/x": false, "file:///x": false, "https:///x": false,
	} {
		if err := checkHTTPURL(u); (err == nil) != ok {
			t.Errorf("checkHTTPURL(%q) = %v, ok want %v", u, err, ok)
		}
	}
}
