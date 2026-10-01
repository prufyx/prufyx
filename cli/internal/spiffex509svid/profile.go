// SPDX-License-Identifier: AGPL-3.0-only

// Package spiffex509svid evaluates a deliberately narrow public-leaf
// X.509-SVID URI-SAN profile. It does not validate a trust chain, possession,
// issuance, or the complete SPIFFE X.509-SVID specification.
package spiffex509svid

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

//go:embed data/profile.json
var embeddedProfileBytes []byte

//go:embed data/capability.json
var embeddedCapabilityBytes []byte

const (
	ProfileAPIVersion      = "prufyx.io/spiffe-x509-svid-profile/v1"
	ProfileKind            = "SPIFFEX509SVIDProfile"
	RuleID                 = "spiffe-x509-svid-public-leaf-uri-san-v1"
	TargetPath             = "knowledge/spiffe-x509-svid-profile.v1.json"
	EngineCapability       = "prufyx.io/spiffe-x509-svid-conformance-engine/v1"
	EngineCapabilityDigest = "sha256:33c6a42388c6d1f340c97dc03179423a1d24d5c92292fea97414c61350f1abbf"
	ConformanceProfileID   = "public-non-ca-leaf-single-spiffe-uri-non-root-path-v1"

	NormativeRepository = "https://github.com/spiffe/spiffe"
	NormativePath       = "standards/X509-SVID.md"
)

var (
	ErrInvalid   = errors.New("invalid SPIFFE X.509-SVID profile")
	ErrIntegrity = errors.New("SPIFFE X.509-SVID profile integrity failure")
	digestRE     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	commitRE     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	revisionRE   = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)
)

type SourceSpan struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
}

type NormativeSource struct {
	RepositoryURL string       `json:"repositoryURL"`
	Path          string       `json:"path"`
	Commit        string       `json:"commit"`
	ContentDigest string       `json:"contentDigest"`
	Spans         []SourceSpan `json:"spans"`
}

type Rule struct {
	ID                string `json:"id"`
	EvidenceExpiresAt string `json:"evidenceExpiresAt"`
}

type Profile struct {
	APIVersion             string          `json:"apiVersion"`
	Kind                   string          `json:"kind"`
	Revision               string          `json:"revision"`
	Purpose                string          `json:"purpose"`
	EngineCapabilityDigest string          `json:"engineCapabilityDigest"`
	NormativeSource        NormativeSource `json:"normativeSource"`
	Rules                  []Rule          `json:"rules"`
	RuleDigest             string          `json:"ruleDigest"`
}

type Admission struct {
	Revision               string
	Purpose                string
	EngineCapabilityDigest string
	HasRule                bool
	RuleDigest             string
	EvidenceExpiresAt      string
}

func AdmitProfile(raw []byte) (Admission, error) {
	p, err := ParseProfile(raw)
	if err != nil {
		return Admission{}, err
	}
	a := Admission{Revision: p.Revision, Purpose: p.Purpose, EngineCapabilityDigest: p.EngineCapabilityDigest, HasRule: len(p.Rules) == 1, RuleDigest: p.RuleDigest}
	if len(p.Rules) == 1 {
		a.EvidenceExpiresAt = p.Rules[0].EvidenceExpiresAt
	}
	return a, nil
}

// EmbeddedProfile returns a private copy of the reviewed initial profile.
func EmbeddedProfile() []byte { return append([]byte(nil), embeddedProfileBytes...) }

func ParseProfile(raw []byte) (Profile, error) {
	if digestBytes(embeddedCapabilityBytes) != EngineCapabilityDigest || len(raw) == 0 || len(raw) > 1<<20 || !utf8.Valid(raw) || scanJSON(raw) != nil {
		return Profile{}, ErrInvalid
	}
	var p Profile
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&p) != nil {
		return Profile{}, ErrInvalid
	}
	if err := d.Decode(&struct{}{}); err != io.EOF || validateProfile(p) != nil {
		return Profile{}, ErrInvalid
	}
	return p, nil
}

func validateProfile(p Profile) error {
	if p.APIVersion != ProfileAPIVersion || p.Kind != ProfileKind || !revisionRE.MatchString(p.Revision) || (p.Purpose != "standards_conformance" && p.Purpose != "synthetic_test_only") || p.EngineCapabilityDigest != EngineCapabilityDigest {
		return ErrInvalid
	}
	s := p.NormativeSource
	if s.RepositoryURL != NormativeRepository || s.Path != NormativePath || !commitRE.MatchString(s.Commit) || !digestRE.MatchString(s.ContentDigest) || len(s.Spans) == 0 || len(s.Spans) > 16 {
		return ErrInvalid
	}
	last := 0
	for _, span := range s.Spans {
		if span.StartLine <= last || span.StartLine < 1 || span.EndLine < span.StartLine || span.EndLine > 10_000_000 {
			return ErrInvalid
		}
		last = span.EndLine
	}
	if len(p.Rules) > 1 {
		return ErrInvalid
	}
	if len(p.Rules) == 0 {
		if p.RuleDigest != "" {
			return ErrInvalid
		}
		return nil
	}
	r := p.Rules[0]
	when, err := parseUTC(r.EvidenceExpiresAt)
	if r.ID != RuleID || err != nil || p.RuleDigest != digestCanonical(struct {
		NormativeSource NormativeSource `json:"normativeSource"`
		Rule            Rule            `json:"rule"`
	}{s, r}) {
		return ErrInvalid
	}
	_ = when
	return nil
}

func parseUTC(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil || t.Location() != time.UTC || t.Nanosecond() != 0 || t.Format(time.RFC3339) != value {
		return time.Time{}, ErrInvalid
	}
	return t, nil
}

func digestCanonical(value any) string {
	raw, _ := json.Marshal(value)
	return digestBytes(raw)
}

func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// scanJSON rejects duplicate and case-fold-colliding object members before
// encoding/json can select one. It also bounds nesting and token count.
func scanJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := scanValue(d, 0, new(int)); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}

func scanValue(d *json.Decoder, depth int, tokens *int) error {
	if depth > 24 || *tokens > 100000 {
		return ErrInvalid
	}
	t, err := d.Token()
	(*tokens)++
	if err != nil {
		return err
	}
	delim, ok := t.(json.Delim)
	if !ok {
		switch v := t.(type) {
		case string:
			if len(v) > 16384 || !utf8.ValidString(v) {
				return ErrInvalid
			}
		case json.Number:
			if len(v.String()) > 64 {
				return ErrInvalid
			}
		}
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			keyToken, e := d.Token()
			if e != nil {
				return e
			}
			key, ok := keyToken.(string)
			if !ok || len(key) > 256 {
				return ErrInvalid
			}
			folded := strings.ToLower(key)
			if seen[folded] {
				return ErrInvalid
			}
			seen[folded] = true
			if e = scanValue(d, depth+1, tokens); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		for d.More() {
			if e := scanValue(d, depth+1, tokens); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

func canonicalProfile(p Profile) ([]byte, error) {
	if validateProfile(p) != nil {
		return nil, ErrInvalid
	}
	raw, err := json.Marshal(p)
	if err != nil {
		return nil, ErrIntegrity
	}
	return raw, nil
}

func MakeProfile(revision, purpose string, source NormativeSource, expires string) ([]byte, error) {
	p := Profile{APIVersion: ProfileAPIVersion, Kind: ProfileKind, Revision: revision, Purpose: purpose, EngineCapabilityDigest: EngineCapabilityDigest, NormativeSource: source, Rules: []Rule{}}
	if expires != "" {
		r := Rule{ID: RuleID, EvidenceExpiresAt: expires}
		p.Rules = []Rule{r}
		p.RuleDigest = digestCanonical(struct {
			NormativeSource NormativeSource `json:"normativeSource"`
			Rule            Rule            `json:"rule"`
		}{source, r})
	}
	return canonicalProfile(p)
}

func (p Profile) Rule() (Rule, bool) {
	if len(p.Rules) != 1 {
		return Rule{}, false
	}
	return p.Rules[0], true
}

func (p Profile) Canonical() ([]byte, error) { return canonicalProfile(p) }

func (p Profile) ValidateAt(at time.Time) error {
	if at.IsZero() || at.Location() != time.UTC {
		return ErrInvalid
	}
	if r, ok := p.Rule(); ok {
		expires, _ := parseUTC(r.EvidenceExpiresAt)
		if !at.Before(expires) {
			return fmt.Errorf("profile evidence expired: %w", ErrInvalid)
		}
	}
	return nil
}
