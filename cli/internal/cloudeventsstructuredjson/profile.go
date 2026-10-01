// SPDX-License-Identifier: AGPL-3.0-only

// Package cloudeventsstructuredjson evaluates a deliberately narrow
// CloudEvents structured JSON core-envelope profile.
package cloudeventsstructuredjson

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
	ProfileAPIVersion      = "prufyx.io/cloudevents-structured-json-profile/v1"
	ProfileKind            = "CloudEventsStructuredJSONProfile"
	RuleID                 = "cloudevents-v1-structured-json-core-envelope-v1"
	TargetPath             = "knowledge/cloudevents-structured-json-profile.v1.json"
	EngineCapability       = "prufyx.io/cloudevents-structured-json-conformance-engine/v1"
	EngineCapabilityDigest = "sha256:94cc3006e46ce20a4c2579eb4d1eb99dfaee9fe00a4396ec3f4ee5ed204313bb"
	ConformanceProfileID   = "structured-json-core-envelope-v1"
	NormativeRepository    = "https://github.com/cloudevents/spec"
)

var (
	ErrInvalid   = errors.New("invalid CloudEvents structured JSON profile")
	ErrIntegrity = errors.New("CloudEvents structured JSON profile integrity failure")
	digestRE     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	commitRE     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	revisionRE   = regexp.MustCompile(`^[1-9][0-9]{0,9}$`)
)

type SourceSpan struct {
	StartLine int `json:"startLine"`
	EndLine   int `json:"endLine"`
}
type NormativeSource struct {
	Role          string       `json:"role"`
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
	APIVersion             string            `json:"apiVersion"`
	Kind                   string            `json:"kind"`
	Revision               string            `json:"revision"`
	Purpose                string            `json:"purpose"`
	EngineCapabilityDigest string            `json:"engineCapabilityDigest"`
	NormativeSources       []NormativeSource `json:"normativeSources"`
	Rules                  []Rule            `json:"rules"`
	RuleDigest             string            `json:"ruleDigest"`
}
type Admission struct {
	Revision, Purpose, EngineCapabilityDigest string
	HasRule                                   bool
	RuleDigest, EvidenceExpiresAt             string
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
	if len(p.NormativeSources) != 2 {
		return ErrInvalid
	}
	roles := map[string]string{"spec": "spec.md", "json-format": "json-format.md"}
	seen := map[string]bool{}
	for _, s := range p.NormativeSources {
		if seen[s.Role] || roles[s.Role] != s.Path || s.RepositoryURL != NormativeRepository || !commitRE.MatchString(s.Commit) || !digestRE.MatchString(s.ContentDigest) || len(s.Spans) == 0 || len(s.Spans) > 16 {
			return ErrInvalid
		}
		seen[s.Role] = true
		last := 0
		for _, span := range s.Spans {
			if span.StartLine <= last || span.StartLine < 1 || span.EndLine < span.StartLine || span.EndLine > 10000000 {
				return ErrInvalid
			}
			last = span.EndLine
		}
	}
	if !seen["spec"] || !seen["json-format"] || len(p.Rules) > 1 {
		return ErrInvalid
	}
	if len(p.Rules) == 0 {
		if p.RuleDigest != "" {
			return ErrInvalid
		}
		return nil
	}
	r := p.Rules[0]
	if _, err := parseUTC(r.EvidenceExpiresAt); r.ID != RuleID || err != nil {
		return ErrInvalid
	}
	if p.RuleDigest != digestCanonical(struct {
		NormativeSources []NormativeSource `json:"normativeSources"`
		Rule             Rule              `json:"rule"`
	}{p.NormativeSources, r}) {
		return ErrInvalid
	}
	return nil
}
func parseUTC(value string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, value)
	if err != nil || t.Location() != time.UTC || t.Nanosecond() != 0 || t.Format(time.RFC3339) != value {
		return time.Time{}, ErrInvalid
	}
	return t, nil
}
func digestCanonical(value any) string { raw, _ := json.Marshal(value); return digestBytes(raw) }
func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
func scanJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := scanProfileValue(d, 0, new(int)); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}
func scanProfileValue(d *json.Decoder, depth int, tokens *int) error {
	if depth > 24 || *tokens > 100000 {
		return ErrInvalid
	}
	t, err := d.Token()
	*tokens++
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
			kt, e := d.Token()
			if e != nil {
				return e
			}
			key, ok := kt.(string)
			if !ok || len(key) > 256 {
				return ErrInvalid
			}
			fold := strings.ToLower(key)
			if seen[fold] {
				return ErrInvalid
			}
			seen[fold] = true
			if e = scanProfileValue(d, depth+1, tokens); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		for d.More() {
			if e := scanProfileValue(d, depth+1, tokens); e != nil {
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
func MakeProfile(revision, purpose string, sources []NormativeSource, expires string) ([]byte, error) {
	p := Profile{APIVersion: ProfileAPIVersion, Kind: ProfileKind, Revision: revision, Purpose: purpose, EngineCapabilityDigest: EngineCapabilityDigest, NormativeSources: sources, Rules: []Rule{}}
	if expires != "" {
		r := Rule{ID: RuleID, EvidenceExpiresAt: expires}
		p.Rules = []Rule{r}
		p.RuleDigest = digestCanonical(struct {
			NormativeSources []NormativeSource `json:"normativeSources"`
			Rule             Rule              `json:"rule"`
		}{sources, r})
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
