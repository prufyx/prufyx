// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// HTTPRefusal contains only canonical, allowlisted response metadata.
// Fields remain private so callers cannot inject arbitrary diagnostic text.
type HTTPRefusal struct {
	status                       int
	remaining, reset, retryAfter string
}

// NewHTTPRefusalReporter returns an invocation-local, once-only stderr sink.
// It does not change fetching, classification, retry or rate-limit policy.
func NewHTTPRefusalReporter(stderr io.Writer) func(HTTPRefusal) {
	if stderr == nil {
		return nil
	}
	var once sync.Once
	return func(d HTTPRefusal) {
		if d.status != 403 && d.status != 429 {
			return
		}
		once.Do(func() {
			line := fmt.Sprintf("evidence repin: http_refusal transport=api status=%d remaining=%s reset_epoch=%s retry_after=%s\n", d.status, d.remaining, d.reset, d.retryAfter)
			if len(line) <= 256 {
				_, _ = io.WriteString(stderr, line)
			}
		})
	}
}

func diagnosticHeader(h http.Header, name string) string {
	values := h.Values(name)
	if len(values) != 1 || len(values[0]) == 0 || len(values[0]) > 64 {
		return ""
	}
	for _, b := range []byte(values[0]) {
		if b < 32 || b > 126 {
			return ""
		}
	}
	return values[0]
}

func diagnosticDecimal(value string, maximum uint64) string {
	if value == "" {
		return "UNKNOWN"
	}
	for _, b := range []byte(value) {
		if b < '0' || b > '9' {
			return "UNKNOWN"
		}
	}
	n, err := strconv.ParseUint(value, 10, 64)
	if err != nil || n > maximum {
		return "UNKNOWN"
	}
	return strconv.FormatUint(n, 10)
}

func parseHTTPRefusal(status int, h http.Header) HTTPRefusal {
	retry := diagnosticHeader(h, "Retry-After")
	retryAfter := diagnosticDecimal(retry, 604800)
	if retryAfter == "UNKNOWN" {
		if date, err := http.ParseTime(retry); err == nil && date.Year() >= 2000 && date.Year() <= 2100 {
			retryAfter = date.UTC().Format(time.RFC3339)
		}
	}
	return HTTPRefusal{
		status:     status,
		remaining:  diagnosticDecimal(diagnosticHeader(h, "X-RateLimit-Remaining"), 1000000000),
		reset:      diagnosticDecimal(diagnosticHeader(h, "X-RateLimit-Reset"), 4102444800),
		retryAfter: retryAfter,
	}
}
