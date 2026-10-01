// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgefetch retrieves a complete knowledge package without
// accepting any local evaluation input or opening a knowledge store.
package knowledgefetch

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

const maxPackageBytes = 4 << 20

var (
	// ErrInvalidSource means the caller did not provide one explicit, absolute
	// HTTPS package URL. It deliberately contains no caller-supplied text.
	ErrInvalidSource = errors.New("invalid knowledge package source")
	// ErrTransfer means the package could not be obtained as one complete,
	// acceptable HTTPS response. It deliberately contains no remote text.
	ErrTransfer = errors.New("knowledge package transfer failed")
	// ErrOversized means either declared or streamed response bytes exceeded
	// the package limit.
	ErrOversized = errors.New("knowledge package response too large")
)

const (
	requestDeadline = 30 * time.Second
	dialTimeout     = 10 * time.Second
	headerTimeout   = 10 * time.Second
	maxHeaderBytes  = 16 << 10
)

// ValidateSource admits only a single, explicit absolute HTTPS URL. The
// complete bundle is selected by this URL alone; no local data is added.
func ValidateSource(source string) error {
	if source == "" || len(source) > 4096 || strings.ContainsAny(source, "?#%") {
		return ErrInvalidSource
	}
	for _, r := range source {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return ErrInvalidSource
		}
	}
	parsed, err := url.ParseRequestURI(source)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Opaque != "" || !parsed.IsAbs() || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.ForceQuery {
		return ErrInvalidSource
	}
	return nil
}

// Fetch obtains one complete package from source. It does not parse package
// bytes, inspect configuration, follow redirects, retry, or write any store.
func Fetch(ctx context.Context, source string) ([]byte, error) {
	return fetchWithClient(ctx, source, newClient(nil))
}

// Tests supply only their own TLS trust and deterministic failure transports.
// Production does not expose or retain mutable client state.
func fetchWithClient(ctx context.Context, source string, client *http.Client) ([]byte, error) {
	if err := ValidateSource(source); err != nil {
		return nil, ErrInvalidSource
	}
	if ctx == nil {
		ctx = context.Background()
	}
	requestContext, cancel := context.WithTimeout(ctx, requestDeadline)
	defer cancel()

	req, err := http.NewRequestWithContext(requestContext, http.MethodGet, source, nil)
	if err != nil {
		return nil, ErrTransfer
	}
	req.Header.Set("Accept", "application/octet-stream")
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("User-Agent", "prufyx-knowledge-fetch/1")

	if client == nil {
		return nil, ErrTransfer
	}
	defer client.CloseIdleConnections()
	response, err := client.Do(req)
	if err != nil {
		return nil, ErrTransfer
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || !identityEncoding(response.Header.Values("Content-Encoding")) {
		return nil, ErrTransfer
	}
	if response.ContentLength > maxPackageBytes {
		return nil, ErrOversized
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, maxPackageBytes+1))
	if err != nil {
		return nil, ErrTransfer
	}
	if len(raw) > maxPackageBytes {
		return nil, ErrOversized
	}
	return bytes.Clone(raw), nil
}

func identityEncoding(values []string) bool {
	return len(values) == 0 || len(values) == 1 && values[0] == "identity"
}

func newClient(testTLS *tls.Config) *http.Client {
	dialer := &net.Dialer{Timeout: dialTimeout, KeepAlive: -1}
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            dialer.DialContext,
		ForceAttemptHTTP2:      false,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		TLSHandshakeTimeout:    dialTimeout,
		ResponseHeaderTimeout:  headerTimeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: maxHeaderBytes,
		TLSClientConfig:        testTLS,
	}
	return &http.Client{
		Transport: transport,
		Timeout:   requestDeadline,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}
