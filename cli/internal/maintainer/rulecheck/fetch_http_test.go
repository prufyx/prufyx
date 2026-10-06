// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPFetcherBoundsAndRedirects(t *testing.T) {
	var otherHits atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		otherHits.Add(1)
		_, _ = w.Write([]byte("elsewhere"))
	}))
	defer other.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("fine")) })
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("a", maxFetchBytes+10)))
	})
	mux.HandleFunc("/cross", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/x", http.StatusFound)
	})
	mux.HandleFunc("/same", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ok", http.StatusFound)
	})
	mux.HandleFunc("/loop", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/loop", http.StatusFound)
	})
	mux.HandleFunc("/missing", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "SECRET-BODY-TEXT", http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tests := []struct {
		name    string
		path    string
		want    string
		wantErr string
	}{
		{"ok", "/ok", "fine", ""},
		{"same host redirect", "/same", "fine", ""},
		{"oversized body", "/big", "", "fetch limit"},
		{"cross host redirect", "/cross", "", "redirect"},
		{"redirect loop", "/loop", "", "redirect"},
		{"status error hides body", "/missing", "", "unexpected status"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			otherHits.Store(0)
			got, err := HTTPFetcher{}.FetchRawBlob(context.Background(), srv.URL+tc.path)
			if tc.wantErr == "" {
				if err != nil || string(got) != tc.want {
					t.Fatalf("got %q, %v; want %q", got, err, tc.want)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("err = %v; want containing %q", err, tc.wantErr)
			}
			if strings.Contains(err.Error(), "SECRET-BODY-TEXT") {
				t.Fatalf("error embeds the response body: %v", err)
			}
			if otherHits.Load() != 0 {
				t.Fatalf("the redirect target on another host was contacted")
			}
		})
	}
}

func TestHTTPFetcherRejectsPlainHTTPAndIgnoresProxyEnv(t *testing.T) {
	var proxyHits atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proxyHits.Add(1)
		_, _ = w.Write([]byte("via-proxy"))
	}))
	defer proxy.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	t.Setenv("http_proxy", proxy.URL)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "")
	t.Setenv("no_proxy", "")

	for _, u := range []string{
		"http://raw.githubusercontent.com.example.test/a/b/c",
		"ftp://raw.githubusercontent.com/a/b/c",
		"file:///etc/passwd",
		"https:///nohost",
	} {
		t.Run(u, func(t *testing.T) {
			if got, err := (HTTPFetcher{}).FetchRawBlob(context.Background(), u); err == nil {
				t.Fatalf("fetched %q, want refusal", got)
			}
		})
	}
	if proxyHits.Load() != 0 {
		t.Fatalf("the environment proxy was contacted %d times", proxyHits.Load())
	}
}

func TestHTTPFetcherTimeout(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	old := fetchTimeout
	fetchTimeout = 150 * time.Millisecond
	defer func() { fetchTimeout = old }()

	for _, name := range []string{"default client", "caller client without timeout"} {
		t.Run(name, func(t *testing.T) {
			f := HTTPFetcher{}
			if name != "default client" {
				f.Client = &http.Client{}
			}
			start := time.Now()
			if _, err := f.FetchRawBlob(context.Background(), srv.URL); err == nil {
				t.Fatal("stalled server fetched without error")
			}
			if time.Since(start) > 5*time.Second {
				t.Fatalf("fetch took %v", time.Since(start))
			}
		})
	}
}

func TestCheckFetchURL(t *testing.T) {
	tests := []struct {
		url string
		ok  bool
	}{
		{"https://raw.githubusercontent.com/a/b/c/d", true},
		{"http://127.0.0.1:8080/x", true},
		{"http://[::1]:8080/x", true},
		{"http://localhost/x", false},
		{"http://raw.githubusercontent.com/a", false},
		{"ftp://raw.githubusercontent.com/a", false},
		{"https:///x", false},
		{"", false},
		{"%zz", false},
	}
	for _, tc := range tests {
		if err := checkFetchURL(tc.url); (err == nil) != tc.ok {
			t.Errorf("checkFetchURL(%q) = %v, ok want %v", tc.url, err, tc.ok)
		}
	}
}

func TestFetchRedirectPolicy(t *testing.T) {
	check := newFetchClient(nil).CheckRedirect
	mk := func(u string) *http.Request { r, _ := http.NewRequest(http.MethodGet, u, nil); return r }
	tests := []struct {
		name string
		to   string
		via  []*http.Request
		ok   bool
	}{
		{"same host", "https://h.example/b", []*http.Request{mk("https://h.example/a")}, true},
		{"other host", "https://evil.example/b", []*http.Request{mk("https://h.example/a")}, false},
		{"downgrade", "http://h.example/b", []*http.Request{mk("https://h.example/a")}, false},
		{"other port", "https://h.example:444/b", []*http.Request{mk("https://h.example/a")}, false},
		{"too many", "https://h.example/b", []*http.Request{mk("https://h.example/a"), mk("https://h.example/a"), mk("https://h.example/a"), mk("https://h.example/a")}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := check(mk(tc.to), tc.via); (err == nil) != tc.ok {
				t.Fatalf("err = %v, ok want %v", err, tc.ok)
			}
		})
	}
}
