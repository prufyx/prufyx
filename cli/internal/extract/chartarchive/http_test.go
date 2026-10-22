// SPDX-License-Identifier: AGPL-3.0-only

package chartarchive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestArchive(t *testing.T) {
	body := []byte("archive bytes")
	var hits atomic.Int64
	mux := http.NewServeMux()
	mux.HandleFunc("/ok.tgz", func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.Write(body) })
	mux.HandleFunc("/missing.tgz", func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); http.NotFound(w, nil) })
	mux.HandleFunc("/error.tgz", func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); http.Error(w, "x", 503) })
	mux.HandleFunc("/big.tgz", func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Write(make([]byte, MaxArchiveBytes+1))
	})
	mux.HandleFunc("/exact.tgz", func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.Write(make([]byte, MaxArchiveBytes))
	})
	mux.HandleFunc("/other.tgz", func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.Write([]byte("other bytes")) })
	mux.HandleFunc("/hop.tgz", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "/ok.tgz", http.StatusFound)
	})
	mux.HandleFunc("/away.tgz", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "http://other.invalid/ok.tgz", http.StatusFound)
	})
	mux.HandleFunc("/loop.tgz", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Redirect(w, r, "/loop.tgz", http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	good := sum(body)
	cases := []struct {
		name, path, digest string
		want               string // "" = success
		fetches            int64
	}{
		{"ok", "/ok.tgz", good, "", 1},
		{"a redirect on the same host", "/hop.tgz", good, "", 2},
		{"a redirect to another host", "/away.tgz", good, "another host or scheme", 1},
		{"a redirect loop", "/loop.tgz", good, "redirects", 4},
		{"not found", "/missing.tgz", good, "HTTP 404", 1},
		{"a server error", "/error.tgz", good, "HTTP 503", 1},
		{"wrong bytes", "/other.tgz", good, "do not hash to the pin", 1},
		{"over the bound", "/big.tgz", sum(make([]byte, MaxArchiveBytes+1)), "size bound", 1},
		{"exactly the bound", "/exact.tgz", sum(make([]byte, MaxArchiveBytes)), "", 1},
		{"a digest that is not a sha256", "/ok.tgz", strings.ToUpper(good), "not a sha256", 0},
		{"a short digest", "/ok.tgz", good[:63], "not a sha256", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hits.Store(0)
			got, err := (&HTTPSource{}).Archive(context.Background(), srv.URL+tc.path, tc.digest)
			if tc.want == "" {
				if err != nil || len(got) == 0 {
					t.Fatalf("%v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.want) || got != nil {
				t.Fatalf("got %d bytes, err %v, want %q", len(got), err, tc.want)
			}
			if hits.Load() != tc.fetches {
				t.Fatalf("%d requests, want %d", hits.Load(), tc.fetches)
			}
		})
	}
	if !errors.Is(func() error {
		_, err := (&HTTPSource{}).Archive(context.Background(), srv.URL+"/big.tgz", sum(make([]byte, MaxArchiveBytes+1)))
		return err
	}(), ErrTooLarge) {
		t.Fatal("the bound is not ErrTooLarge")
	}
}

func TestArchiveRefusesURLs(t *testing.T) {
	for _, u := range []string{"http://example.org/a.tgz", "ftp://example.org/a.tgz", "file:///etc/passwd", "https://user:pw@example.org/a.tgz", "https:///a.tgz", "://", "oci://example.org/a"} {
		s := &HTTPSource{Admit: func() error { t.Errorf("admitted %s", u); return nil }}
		if _, err := s.Archive(context.Background(), u, strings.Repeat("a", 64)); err == nil {
			t.Errorf("%s was fetched", u)
		}
	}
}

// Admit is asked before every request, and a refusal sends nothing.
func TestArchiveAdmit(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.Write([]byte("x")) }))
	defer srv.Close()
	stop := errors.New("budget used up")
	if _, err := (&HTTPSource{Admit: func() error { return stop }}).Archive(context.Background(), srv.URL+"/a.tgz", sum([]byte("x"))); !errors.Is(err, stop) || hits.Load() != 0 {
		t.Fatalf("err %v, %d requests", err, hits.Load())
	}
	var asked int
	s := &HTTPSource{Admit: func() error { asked++; return nil }}
	if _, err := s.Archive(context.Background(), srv.URL+"/a.tgz", sum([]byte("x"))); err != nil || asked != 1 || hits.Load() != 1 {
		t.Fatalf("err %v asked %d requests %d", err, asked, hits.Load())
	}
}

func TestArchiveContext(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := (&HTTPSource{}).Archive(ctx, srv.URL+"/a.tgz", strings.Repeat("a", 64)); err == nil || time.Since(start) > 10*time.Second {
		t.Fatalf("err %v after %v", err, time.Since(start))
	}
}

// A cached archive is used only if it hashes to its name.
func TestArchiveCache(t *testing.T) {
	body := []byte("archive bytes")
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits.Add(1); w.Write(body) }))
	defer srv.Close()
	dir := t.TempDir()
	s := &HTTPSource{CacheDir: filepath.Join(dir, "cache")}
	digest := sum(body)
	if _, err := s.Archive(context.Background(), srv.URL+"/a.tgz", digest); err != nil || hits.Load() != 1 {
		t.Fatalf("first: %v, %d requests", err, hits.Load())
	}
	// The second call is answered from the disk.
	srv.Close()
	got, err := s.Archive(context.Background(), srv.URL+"/a.tgz", digest)
	if err != nil || string(got) != string(body) || hits.Load() != 1 {
		t.Fatalf("second: %v %q, %d requests", err, got, hits.Load())
	}
	// A tampered entry is a miss, never a wrong answer.
	p := filepath.Join(dir, "cache", digest+".tgz")
	if err := os.WriteFile(p, []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Archive(context.Background(), srv.URL+"/a.tgz", digest); err == nil {
		t.Fatal("a tampered cache entry was returned")
	}
	// So is a link to the right bytes.
	real := filepath.Join(dir, "real")
	if err := os.WriteFile(real, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, p); err != nil {
		t.Skip("no symlinks")
	}
	if _, err := s.Archive(context.Background(), srv.URL+"/a.tgz", digest); err == nil {
		t.Fatal("a linked cache entry was returned")
	}
	// Bytes that do not verify are not stored.
	other := &HTTPSource{CacheDir: filepath.Join(dir, "other")}
	hits.Store(0)
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("wrong")) }))
	defer srv2.Close()
	if _, err := other.Archive(context.Background(), srv2.URL+"/a.tgz", digest); err == nil {
		t.Fatal("wrong bytes were returned")
	}
	if _, err := os.Stat(filepath.Join(dir, "other", digest+".tgz")); err == nil {
		t.Fatal("wrong bytes were cached")
	}
}
