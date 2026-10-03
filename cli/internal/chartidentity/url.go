// SPDX-License-Identifier: AGPL-3.0-only

package chartidentity

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"unicode"
)

var (
	hostRE    = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:[0-9]{1,5})?$`)
	segmentRE = regexp.MustCompile(`^[A-Za-z0-9._~+-]+$`)
)

// NormalizeRepoURL returns the canonical form of a chart repository URL: the
// scheme is https or oci, the host is lower-case, a trailing "/" and a
// trailing ".git" are removed, and nothing else (userinfo, query, fragment,
// percent escapes, empty or dot segments) is accepted. Lookups key on this
// form; callers must use this function to build keys.
func NormalizeRepoURL(raw string) (string, error) {
	if raw == "" || len(raw) > 2048 {
		return "", fmt.Errorf("repository URL: %w", ErrInvalid)
	}
	for _, r := range raw {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return "", fmt.Errorf("repository URL: %w", ErrInvalid)
		}
	}
	if strings.ContainsAny(raw, "?#%@\\") {
		return "", fmt.Errorf("repository URL carries a query, fragment, userinfo or escape: %w", ErrInvalid)
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", fmt.Errorf("repository URL: %w", ErrInvalid)
	}
	if u.Scheme != "https" && u.Scheme != "oci" {
		return "", fmt.Errorf("repository URL scheme must be https or oci: %w", ErrInvalid)
	}
	host := strings.ToLower(u.Host)
	if !hostRE.MatchString(host) {
		return "", fmt.Errorf("repository URL host: %w", ErrInvalid)
	}
	p := strings.TrimRight(u.Path, "/")
	p = strings.TrimSuffix(p, ".git")
	if p != "" {
		if !strings.HasPrefix(p, "/") {
			return "", fmt.Errorf("repository URL path: %w", ErrInvalid)
		}
		for _, seg := range strings.Split(p[1:], "/") {
			if seg == "." || seg == ".." || !segmentRE.MatchString(seg) {
				return "", fmt.Errorf("repository URL path segment: %w", ErrInvalid)
			}
		}
	}
	return u.Scheme + "://" + host + p, nil
}
