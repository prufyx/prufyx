// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

// maxFetchBytes bounds a downloaded blob. Source files cited by a rule are
// small text/code files; anything larger indicates the wrong target.
const maxFetchBytes = 8 << 20

// fetchTimeout bounds one whole request, body included; a server that stalls
// or trickles bytes fails the fetch instead of hanging the check.
var fetchTimeout = 60 * time.Second

const maxFetchRedirects = 3

// noProxyTransport is the default transport minus proxy environment lookup.
var noProxyTransport = func() *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.Proxy = nil
	return t
}()

// newFetchClient returns the one HTTP client this package uses. It ignores
// proxy environment variables, applies fetchTimeout, and follows redirects
// only within the original host and scheme (so never to another host and
// never from https to http).
func newFetchClient(base *http.Client) *http.Client {
	var c http.Client
	if base != nil {
		c = *base
	} else {
		c.Transport = noProxyTransport
	}
	if c.Timeout <= 0 || c.Timeout > fetchTimeout {
		c.Timeout = fetchTimeout
	}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > maxFetchRedirects {
			return fmt.Errorf("stopped after %d redirects", maxFetchRedirects)
		}
		first := via[0].URL
		if req.URL.Scheme != first.Scheme || req.URL.Host != first.Host {
			return fmt.Errorf("redirect to another host or scheme refused")
		}
		return nil
	}
	return &c
}

// checkFetchURL refuses anything but https, except plain http to a loopback
// address (local test servers).
func checkFetchURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Hostname() == "" {
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

// HTTPFetcher is the production Fetcher: a plain net/http GET restricted to
// raw.githubusercontent.com by construction (Validate only ever builds URLs
// on that host from an already-validated github.com blob URL).
type HTTPFetcher struct {
	Client *http.Client
}

func (f HTTPFetcher) FetchRawBlob(ctx context.Context, rawURL string) ([]byte, error) {
	if err := checkFetchURL(rawURL); err != nil {
		return nil, err
	}
	client := newFetchClient(f.Client)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s fetching %s", response.Status, rawURL)
	}
	limited := io.LimitReader(response.Body, maxFetchBytes+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(content) > maxFetchBytes {
		return nil, fmt.Errorf("%s exceeds the %d byte fetch limit", rawURL, maxFetchBytes)
	}
	return content, nil
}
