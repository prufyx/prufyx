// SPDX-License-Identifier: AGPL-3.0-only

package chartidentity

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"
)

const (
	maxRecords = 2048
	maxSources = 8
	timeLayout = "2006-01-02T15:04:05Z"
)

var (
	idRE        = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,127}$`)
	chartRE     = idRE
	componentRE = regexp.MustCompile(`^pkg:[a-z0-9][a-z0-9+._/-]{2,255}$`)
	revisionRE  = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestRE    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	versionRE   = regexp.MustCompile(`^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	pathPartRE  = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
)

// Source is one cited span of one file at a pinned commit.
type Source struct {
	ID            string `json:"id"`
	URL           string `json:"url"`
	Revision      string `json:"revision"`
	ContentDigest string `json:"contentDigest"`
	StartLine     int    `json:"startLine"`
	EndLine       int    `json:"endLine"`
}

// Extractor names the code that derived a mechanical record.
type Extractor struct {
	ID         string `json:"id"`
	Version    string `json:"version"`
	CodeDigest string `json:"codeDigest"`
}

// NormalizeVersion removes one optional leading "v" and accepts only a
// strict X.Y.Z (no pre-release, build metadata, ranges or leading zeros).
func NormalizeVersion(v string) (string, bool) {
	v = strings.TrimPrefix(v, "v")
	if !versionRE.MatchString(v) {
		return "", false
	}
	return v, true
}

func parseTime(s string) (time.Time, error) {
	t, err := time.Parse(timeLayout, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("time %q: %w", s, ErrInvalid)
	}
	return t, nil
}

func validateSources(sources []Source) error {
	if len(sources) == 0 || len(sources) > maxSources {
		return fmt.Errorf("source count: %w", ErrInvalid)
	}
	for i, s := range sources {
		if i > 0 && sources[i-1].ID >= s.ID {
			return fmt.Errorf("source order: %w", ErrInvalid)
		}
		if !idRE.MatchString(s.ID) || !revisionRE.MatchString(s.Revision) || !digestRE.MatchString(s.ContentDigest) {
			return fmt.Errorf("source identity: %w", ErrInvalid)
		}
		if s.StartLine < 1 || s.EndLine < s.StartLine || s.EndLine > 1_000_000 {
			return fmt.Errorf("source span: %w", ErrInvalid)
		}
		if !immutableGitURL(s.URL, s.Revision) {
			return fmt.Errorf("source URL: %w", ErrInvalid)
		}
	}
	return nil
}

func immutableGitURL(value, revision string) bool {
	if len(value) == 0 || len(value) > 2048 || strings.Contains(value, "%") {
		return false
	}
	for _, r := range value {
		if unicode.IsControl(r) {
			return false
		}
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Port() != "" || u.RawQuery != "" || u.Fragment != "" || (u.Host != "github.com" && u.Host != "raw.githubusercontent.com") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	if len(parts) < 4 || !pathPartRE.MatchString(parts[0]) || !pathPartRE.MatchString(parts[1]) {
		return false
	}
	if u.Host == "github.com" {
		if parts[2] != "blob" || parts[3] != revision || len(parts) < 5 {
			return false
		}
		parts = parts[4:]
	} else {
		if parts[2] != revision {
			return false
		}
		parts = parts[3:]
	}
	for _, p := range parts {
		if p == "." || p == ".." || !pathPartRE.MatchString(p) {
			return false
		}
	}
	return true
}
