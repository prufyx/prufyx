// SPDX-License-Identifier: AGPL-3.0-only

// Package chartarchive fetches the packaged Helm charts that a reviewed target
// pins by URL and sha256 (crdversions.ArchiveSource). Bytes that do not hash to
// the pin are never returned, whatever served them.
package chartarchive

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"time"
)

// Limits of one fetch.
const (
	// MaxArchiveBytes bounds the compressed archive.
	MaxArchiveBytes = 10 << 20
	// Timeout bounds one whole request, body included. The context of the
	// caller bounds it further.
	Timeout = 60 * time.Second

	maxRedirects = 3
)

var digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

// ErrTooLarge reports an archive over MaxArchiveBytes.
var ErrTooLarge = errors.New("the archive is over the size bound")

// noProxyTransport is the default transport minus proxy environment lookup.
var noProxyTransport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return t
}()

// HTTPSource fetches an archive with one HTTPS GET. It ignores proxy
// environment variables and follows redirects only within the original host
// and scheme, as the knowledge gate's GitHub source does.
type HTTPSource struct {
	// Client defaults to a client without proxy lookup; its timeout is
	// capped at Timeout.
	Client *http.Client
	// CacheDir, when set, keeps verified archives on disk under their
	// sha256. An entry is used only if its bytes hash to its name; any
	// failure to read or write the cache is silent.
	CacheDir string
	// Admit, when set, is called before every network request; an error
	// stops the fetch (the caller's request budget is used up).
	Admit func() error
}

// Archive implements extract.ArchiveSource.
func (s *HTTPSource) Archive(ctx context.Context, rawURL, digest string) ([]byte, error) {
	if !digestRE.MatchString(digest) {
		return nil, fmt.Errorf("the pin %q is not a sha256", digest)
	}
	if err := checkURL(rawURL); err != nil {
		return nil, err
	}
	if b, ok := s.load(digest); ok {
		return b, nil
	}
	if s.Admit != nil {
		if err := s.Admit(); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client().Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetching %s: HTTP %d", rawURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxArchiveBytes+1))
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", rawURL, err)
	}
	if len(body) > MaxArchiveBytes {
		return nil, fmt.Errorf("fetching %s: %w (%d bytes)", rawURL, ErrTooLarge, MaxArchiveBytes)
	}
	if hashOf(body) != digest {
		return nil, fmt.Errorf("fetching %s: the bytes do not hash to the pin %s", rawURL, digest)
	}
	s.store(digest, body)
	return body, nil
}

func hashOf(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// checkURL accepts https, and plain http to a loopback address (local test
// servers).
func checkURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" || u.User != nil {
		return fmt.Errorf("not a fetchable URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if ip := net.ParseIP(u.Hostname()); ip != nil && ip.IsLoopback() {
			return nil
		}
	}
	return fmt.Errorf("only https URLs are fetched")
}

func (s *HTTPSource) client() *http.Client {
	var c http.Client
	if s.Client != nil {
		c = *s.Client
	} else {
		c.Transport = noProxyTransport
	}
	if c.Timeout <= 0 || c.Timeout > Timeout {
		c.Timeout = Timeout
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return fmt.Errorf("stopped after %d redirects", maxRedirects)
		}
		first := via[0].URL
		if req.URL.Scheme != first.Scheme || req.URL.Host != first.Host {
			return fmt.Errorf("redirect to another host or scheme refused")
		}
		return nil
	}
	return &c
}

func (s *HTTPSource) path(digest string) string {
	if s.CacheDir == "" {
		return ""
	}
	return filepath.Join(s.CacheDir, digest+".tgz")
}

// load returns a cached archive, only if it is a regular file within the
// bound that hashes to its name.
func (s *HTTPSource) load(digest string) ([]byte, bool) {
	p := s.path(digest)
	if p == "" {
		return nil, false
	}
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > MaxArchiveBytes {
		return nil, false
	}
	b, err := os.ReadFile(p) // #nosec G304 -- p is the cache directory plus a validated sha256
	if err != nil || len(b) > MaxArchiveBytes || hashOf(b) != digest {
		return nil, false
	}
	return b, true
}

func (s *HTTPSource) store(digest string, b []byte) {
	p := s.path(digest)
	if p == "" {
		return
	}
	if err := os.MkdirAll(s.CacheDir, 0o750); err != nil {
		return
	}
	f, err := os.CreateTemp(s.CacheDir, ".tmp-*")
	if err != nil {
		return
	}
	_, werr := f.Write(b)
	cerr := f.Close()
	if werr != nil || cerr != nil || os.Rename(f.Name(), p) != nil {
		_ = os.Remove(f.Name())
	}
}
