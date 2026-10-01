// SPDX-License-Identifier: AGPL-3.0-only

// Package tikvgcpv2 evaluates the closed TiKV 8.5.8 planned GCS full-backup
// Workload Identity Federation setting profile.
package tikvgcpv2

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	ProfileAPIVersion      = "prufyx.io/tikv-gcp-v2-wif-backup-profile/v1"
	ProfileKind            = "TiKVGCPV2WIFBackupProfile"
	RuleID                 = "tikv-8.5.8-gcp-v2-wif-full-backup-enabled-v1"
	TargetPath             = "knowledge/tikv-gcp-v2-wif-backup-profile.v1.json"
	EngineCapability       = "prufyx.io/tikv-gcp-v2-wif-backup-engine/v1"
	EngineCapabilityDigest = "sha256:f342ee3a3a997add0a234937499a8e2327baad4e4329b12b590e6e5fb1528d8a"
	ProfileID              = "tikv-8.5.8-gcp-v2-wif-full-backup-v1"
	TiKVRepository         = "https://github.com/tikv/tikv"
	DocsRepository         = "https://github.com/pingcap/docs"
)

var (
	ErrInvalid   = errors.New("invalid TiKV GCP v2 WIF backup profile")
	ErrIntegrity = errors.New("TiKV GCP v2 WIF backup profile integrity failure")
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
type Target struct {
	Component string `json:"component"`
	Version   string `json:"version"`
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
	Target                 Target            `json:"target"`
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
	p, e := ParseProfile(raw)
	if e != nil {
		return Admission{}, e
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
	if e := d.Decode(&struct{}{}); e != io.EOF || validateProfile(p) != nil {
		return Profile{}, ErrInvalid
	}
	return p, nil
}
func validateProfile(p Profile) error {
	if p.APIVersion != ProfileAPIVersion || p.Kind != ProfileKind || !revisionRE.MatchString(p.Revision) || (p.Purpose != "planned_operation_preflight" && p.Purpose != "synthetic_test_only") || p.EngineCapabilityDigest != EngineCapabilityDigest || p.Target.Component != Component || p.Target.Version != "8.5.8" || len(p.NormativeSources) != 3 || len(p.Rules) > 1 {
		return ErrInvalid
	}
	type expected struct{ repo, path string }
	roles := map[string]expected{"target_setting_declaration": {TiKVRepository, "src/config/mod.rs"}, "target_full_backup_caller": {TiKVRepository, "components/backup/src/endpoint.rs"}, "operator_action_guidance": {DocsRepository, "tikv-configuration-file.md"}}
	seen := map[string]bool{}
	tikvCommit := ""
	for _, s := range p.NormativeSources {
		x, ok := roles[s.Role]
		if !ok || seen[s.Role] || s.RepositoryURL != x.repo || s.Path != x.path || !commitRE.MatchString(s.Commit) || !digestRE.MatchString(s.ContentDigest) || len(s.Spans) == 0 || len(s.Spans) > 16 {
			return ErrInvalid
		}
		seen[s.Role] = true
		if s.RepositoryURL == TiKVRepository {
			if tikvCommit == "" {
				tikvCommit = s.Commit
			} else if tikvCommit != s.Commit {
				return ErrInvalid
			}
		}
		last := 0
		for _, sp := range s.Spans {
			if sp.StartLine <= last || sp.StartLine < 1 || sp.EndLine < sp.StartLine || sp.EndLine > 10000000 {
				return ErrInvalid
			}
			last = sp.EndLine
		}
	}
	if len(seen) != 3 {
		return ErrInvalid
	}
	if len(p.Rules) == 0 {
		if p.RuleDigest != "" {
			return ErrInvalid
		}
		return nil
	}
	rule := p.Rules[0]
	if _, e := parseUTC(rule.EvidenceExpiresAt); rule.ID != RuleID || e != nil {
		return ErrInvalid
	}
	if p.RuleDigest != digestCanonical(struct {
		Target           Target            `json:"target"`
		NormativeSources []NormativeSource `json:"normativeSources"`
		Rule             Rule              `json:"rule"`
	}{p.Target, p.NormativeSources, rule}) {
		return ErrInvalid
	}
	return nil
}
func parseUTC(v string) (time.Time, error) {
	t, e := time.Parse(time.RFC3339, v)
	if e != nil || t.Location() != time.UTC || t.Nanosecond() != 0 || t.Format(time.RFC3339) != v {
		return time.Time{}, ErrInvalid
	}
	return t, nil
}
func digestCanonical(v any) string { b, _ := json.Marshal(v); return digestBytes(b) }
func digestBytes(b []byte) string  { s := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(s[:]) }
func scanJSON(raw []byte) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	n := 0
	if e := scanValue(d, 0, &n); e != nil {
		return e
	}
	if _, e := d.Token(); e != io.EOF {
		return ErrInvalid
	}
	return nil
}
func scanValue(d *json.Decoder, depth int, n *int) error {
	if depth > 24 || *n > 100000 {
		return ErrInvalid
	}
	t, e := d.Token()
	*n++
	if e != nil {
		return e
	}
	delim, ok := t.(json.Delim)
	if !ok {
		if s, ok := t.(string); ok && (len(s) > 16384 || !utf8.ValidString(s)) {
			return ErrInvalid
		}
		if x, ok := t.(json.Number); ok && len(x.String()) > 64 {
			return ErrInvalid
		}
		return nil
	}
	switch delim {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			k, e := d.Token()
			if e != nil {
				return e
			}
			s, ok := k.(string)
			if !ok || len(s) > 256 {
				return ErrInvalid
			}
			fold := strings.ToLower(s)
			if seen[fold] {
				return ErrInvalid
			}
			seen[fold] = true
			if e = scanValue(d, depth+1, n); e != nil {
				return e
			}
		}
		end, e := d.Token()
		if e != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		for d.More() {
			if e := scanValue(d, depth+1, n); e != nil {
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
	b, e := json.Marshal(p)
	if e != nil {
		return nil, ErrIntegrity
	}
	return b, nil
}
func MakeProfile(revision, purpose string, sources []NormativeSource, expires string) ([]byte, error) {
	p := Profile{APIVersion: ProfileAPIVersion, Kind: ProfileKind, Revision: revision, Purpose: purpose, EngineCapabilityDigest: EngineCapabilityDigest, Target: Target{Component: Component, Version: "8.5.8"}, NormativeSources: sources, Rules: []Rule{}}
	if expires != "" {
		r := Rule{ID: RuleID, EvidenceExpiresAt: expires}
		p.Rules = []Rule{r}
		p.RuleDigest = digestCanonical(struct {
			Target           Target            `json:"target"`
			NormativeSources []NormativeSource `json:"normativeSources"`
			Rule             Rule              `json:"rule"`
		}{p.Target, sources, r})
	}
	return canonicalProfile(p)
}
func (p Profile) Rule() (Rule, bool) {
	if len(p.Rules) != 1 {
		return Rule{}, false
	}
	return p.Rules[0], true
}
