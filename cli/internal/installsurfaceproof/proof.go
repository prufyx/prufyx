// SPDX-License-Identifier: AGPL-3.0-only

// Package installsurfaceproof defines bounded installation evidence and its
// offline replay boundary. It is not connected to admission or signing.
// Callers must authenticate policy against BASE and supply independent complete
// materialization and approved renderer implementations. None are provided here.
package installsurfaceproof

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
)

const Schema = "prufyx.io/install-surface-proof/v1"

const (
	MaxProofBytes      = 4 << 20
	MaxArchiveBytes    = 32 << 20
	MaxExpandedBytes   = 128 << 20
	MaxFiles           = 4096
	MaxFileBytes       = 8 << 20
	MaxDepth           = 32
	MaxPathBytes       = 240
	MaxDependencies    = 16
	MaxDependencyDepth = 4
	MaxValuesBytes     = 256 << 10
	MaxCapabilities    = 256
	MaxRenderedBytes   = 16 << 20
	MaxResources       = 1024
)

type Tuple struct {
	Project       string   `json:"project"`
	Component     string   `json:"component"`
	Surface       string   `json:"surface"`
	AppRepository string   `json:"appRepository"`
	AppTag        string   `json:"appTag"`
	AppCommit     string   `json:"appCommit"`
	From          string   `json:"from"`
	To            string   `json:"to"`
	ConfigID      string   `json:"configId"`
	Families      []string `json:"families"`
}

type Source struct {
	Repository string `json:"repository"`
	Commit     string `json:"commit"`
	Directory  string `json:"directory"`
	Tree       string `json:"tree"`
}

type Origin struct {
	IndexURL      string `json:"indexUrl"`
	IndexDigest   string `json:"indexDigest"`
	ChartName     string `json:"chartName"`
	ChartVersion  string `json:"chartVersion"`
	AppVersion    string `json:"appVersion"`
	ArchiveURL    string `json:"archiveUrl"`
	ArchiveDigest string `json:"archiveDigest"`
	Source        Source `json:"source"`
	ObservedAt    string `json:"observedAt"`
	ExpiresAt     string `json:"expiresAt"`
}

type File struct {
	Path    string `json:"path"`
	Mode    string `json:"mode"`
	Size    int64  `json:"size"`
	GitBlob string `json:"gitBlob"`
	Digest  string `json:"digest"`
}

type Dependency struct {
	CaseID          string `json:"caseId"`
	ProofDigest     string `json:"proofDigest"`
	Depth           int    `json:"depth"`
	Enabled         bool   `json:"enabled"`
	PredicateDigest string `json:"predicateDigest"`
}

type Artifact struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

type Render struct {
	Version           string     `json:"version"`
	BinaryDigest      string     `json:"binaryDigest"`
	ImageDigest       string     `json:"imageDigest"`
	KubernetesVersion string     `json:"kubernetesVersion"`
	Capabilities      []string   `json:"capabilities"`
	Values            []Artifact `json:"values"`
	Flags             []string   `json:"flags"`
	CPUMillis         int        `json:"cpuMillis"`
	MemoryMiB         int        `json:"memoryMiB"`
	PIDs              int        `json:"pids"`
	TimeoutSeconds    int        `json:"timeoutSeconds"`
}

// Output inventories are assertions until independently extracted from the
// complete rerendered bytes by the required materializer implementation.
type Output struct {
	Digest    string `json:"digest"`
	Resources []File `json:"resources"`
	CRDs      []CRD  `json:"crds"`
}

type CRDVersion struct {
	Name         string `json:"name"`
	Served       bool   `json:"served"`
	Storage      bool   `json:"storage"`
	SchemaDigest string `json:"schemaDigest"`
}

type CRD struct {
	Group    string       `json:"group"`
	Kind     string       `json:"kind"`
	Name     string       `json:"name"`
	Versions []CRDVersion `json:"versions"`
}

type Proof struct {
	Schema           string       `json:"schema"`
	Tuple            Tuple        `json:"tuple"`
	Origin           Origin       `json:"origin"`
	ArchiveInventory []File       `json:"archiveInventory"`
	SourceInventory  []File       `json:"sourceInventory"`
	ChartLockDigest  string       `json:"chartLockDigest"`
	Dependencies     []Dependency `json:"dependencies"`
	Render           Render       `json:"render"`
	Output           Output       `json:"output"`
}

var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var objectRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
var projectRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)
var caseRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func Digest(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

func ascii(s string) bool {
	if s == "" || len(s) > 2048 {
		return false
	}
	for _, c := range s {
		if c < 32 || c > 126 {
			return false
		}
	}
	return true
}

func validPath(s string) bool {
	if !ascii(s) || len(s) > MaxPathBytes || path.IsAbs(s) || path.Clean(s) != s || strings.ContainsAny(s, "\\:") {
		return false
	}
	parts := strings.Split(s, "/")
	if len(parts) > MaxDepth {
		return false
	}
	for _, p := range parts {
		if p == "." || p == ".." || p == "" {
			return false
		}
	}
	return true
}

func sortedUnique(s []string, max int) bool {
	if len(s) > max || !sort.StringsAreSorted(s) {
		return false
	}
	for i, v := range s {
		if !ascii(v) || i > 0 && v == s[i-1] {
			return false
		}
	}
	return true
}

func (t Tuple) validate() error {
	if !projectRE.MatchString(t.Project) || !ascii(t.Component) || !ascii(t.AppRepository) || !ascii(t.AppTag) || !objectRE.MatchString(t.AppCommit) || !ascii(t.From) || !ascii(t.To) || !ascii(t.ConfigID) || len(t.Families) == 0 || !sortedUnique(t.Families, MaxCapabilities) {
		return errors.New("invalid frozen tuple")
	}
	if t.Surface != "raw" && t.Surface != "helm" && t.Surface != "olm" {
		return errors.New("unsupported surface")
	}
	return nil
}

// CaseID hashes only the frozen tuple. It confers no authority and never hashes
// the proof itself or a future approval commit.
func (t Tuple) CaseID() (string, error) {
	if err := t.validate(); err != nil {
		return "", err
	}
	b, err := json.Marshal(t)
	if err != nil {
		return "", err
	}
	return strings.TrimPrefix(Digest(b), "sha256:"), nil
}

func (t Tuple) PublicPath() (string, error) {
	id, err := t.CaseID()
	if err != nil {
		return "", err
	}
	return "cli/knowledge/install-surfaces/" + t.Project + "/" + id + ".json", nil
}

func inventory(files []File, maxFiles int, maxBytes int64) error {
	if len(files) == 0 || len(files) > maxFiles {
		return errors.New("inventory count outside bound")
	}
	var total int64
	for i, f := range files {
		if !validPath(f.Path) || i > 0 && files[i-1].Path >= f.Path || f.Mode != "100644" && f.Mode != "100755" || f.Size < 0 || f.Size > MaxFileBytes || !digestRE.MatchString(f.Digest) || f.GitBlob != "" && !objectRE.MatchString(f.GitBlob) {
			return errors.New("invalid inventory entry")
		}
		total += f.Size
		if total > maxBytes {
			return errors.New("inventory byte bound exceeded")
		}
	}
	return nil
}

func (p Proof) validate() error {
	if p.Schema != Schema {
		return errors.New("wrong proof schema")
	}
	if err := p.Tuple.validate(); err != nil {
		return err
	}
	o := p.Origin
	for _, s := range []string{o.ChartName, o.ChartVersion, o.AppVersion, o.Source.Repository, p.Render.Version, p.Render.KubernetesVersion} {
		if !ascii(s) {
			return errors.New("missing source or render identity")
		}
	}
	for _, s := range []string{o.IndexURL, o.ArchiveURL} {
		u, e := url.Parse(s)
		if e != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" || !ascii(s) {
			return errors.New("invalid public source URL")
		}
	}
	for _, s := range []string{o.IndexDigest, o.ArchiveDigest, p.ChartLockDigest, p.Render.BinaryDigest, p.Render.ImageDigest, p.Output.Digest} {
		if !digestRE.MatchString(s) {
			return errors.New("invalid digest")
		}
	}
	if !objectRE.MatchString(o.Source.Commit) || !objectRE.MatchString(o.Source.Tree) || !validPath(o.Source.Directory) {
		return errors.New("invalid pinned source")
	}
	observed, e1 := time.Parse(time.RFC3339, o.ObservedAt)
	expires, e2 := time.Parse(time.RFC3339, o.ExpiresAt)
	if e1 != nil || e2 != nil || observed.UTC().Format(time.RFC3339) != o.ObservedAt || expires.UTC().Format(time.RFC3339) != o.ExpiresAt || !expires.After(observed) {
		return errors.New("invalid observation window")
	}
	if err := inventory(p.ArchiveInventory, MaxFiles, MaxExpandedBytes); err != nil {
		return err
	}
	if err := inventory(p.SourceInventory, MaxFiles, MaxExpandedBytes); err != nil {
		return err
	}
	for _, f := range p.SourceInventory {
		if !objectRE.MatchString(f.GitBlob) {
			return errors.New("missing source Git blob")
		}
	}
	if len(p.Dependencies) > MaxDependencies || p.Dependencies == nil {
		return errors.New("invalid dependency set")
	}
	for i, d := range p.Dependencies {
		if !caseRE.MatchString(d.CaseID) || i > 0 && p.Dependencies[i-1].CaseID >= d.CaseID || !digestRE.MatchString(d.ProofDigest) || !digestRE.MatchString(d.PredicateDigest) || d.Depth < 1 || d.Depth > MaxDependencyDepth {
			return errors.New("invalid dependency")
		}
	}
	r := p.Render
	if r.Capabilities == nil || !sortedUnique(r.Capabilities, MaxCapabilities) || r.Values == nil || r.Flags == nil || len(r.Values) > MaxFiles || len(r.Flags) > 64 || r.CPUMillis < 1 || r.CPUMillis > 4000 || r.MemoryMiB < 1 || r.MemoryMiB > 4096 || r.PIDs < 1 || r.PIDs > 256 || r.TimeoutSeconds < 1 || r.TimeoutSeconds > 300 {
		return errors.New("invalid render configuration or bounds")
	}
	seen := map[string]bool{}
	for _, a := range r.Values {
		if !validPath(a.Path) || !digestRE.MatchString(a.Digest) || seen[a.Path] {
			return errors.New("invalid or duplicate values artifact")
		}
		seen[a.Path] = true
	}
	for _, s := range r.Flags {
		if !ascii(s) {
			return errors.New("invalid render flag")
		}
	}
	if err := inventory(p.Output.Resources, MaxResources, MaxRenderedBytes); err != nil {
		return err
	}
	if p.Output.CRDs == nil || len(p.Output.CRDs) > MaxResources {
		return errors.New("invalid CRD inventory")
	}
	last := ""
	for _, c := range p.Output.CRDs {
		key := c.Group + "/" + c.Name
		if !ascii(c.Group) || !ascii(c.Kind) || !ascii(c.Name) || key <= last || len(c.Versions) == 0 || len(c.Versions) > 64 {
			return errors.New("invalid CRD identity")
		}
		last = key
		previous := ""
		storage := 0
		for _, v := range c.Versions {
			if !ascii(v.Name) || v.Name <= previous || !digestRE.MatchString(v.SchemaDigest) {
				return errors.New("invalid CRD version")
			}
			previous = v.Name
			if v.Storage {
				storage++
			}
		}
		if storage != 1 {
			return errors.New("CRD needs exactly one storage version")
		}
	}
	return nil
}

// uniqueJSON checks every object before decoding into a closed typed schema.
func uniqueJSON(d *json.Decoder, depth int) error {
	if depth > MaxDepth {
		return errors.New("JSON depth bound exceeded")
	}
	t, err := d.Token()
	if err != nil {
		return err
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			seen := map[string]bool{}
			for d.More() {
				k, e := d.Token()
				if e != nil {
					return e
				}
				s, ok := k.(string)
				if !ok || seen[s] {
					return errors.New("duplicate JSON member")
				}
				seen[s] = true
				if err := uniqueJSON(d, depth+1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := uniqueJSON(d, depth+1); err != nil {
					return err
				}
			}
		default:
			return errors.New("unexpected JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	return nil
}

func Decode(raw []byte) (Proof, error) {
	var p Proof
	if len(raw) == 0 || len(raw) > MaxProofBytes {
		return p, errors.New("proof byte bound exceeded")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := uniqueJSON(d, 0); err != nil {
		return p, err
	}
	if _, err := d.Token(); err != io.EOF {
		return p, errors.New("trailing JSON")
	}
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, err
	}
	if err := p.validate(); err != nil {
		return p, err
	}
	canonical, err := json.Marshal(p)
	if err != nil {
		return p, err
	}
	if !bytes.Equal(raw, canonical) {
		return p, errors.New("noncanonical proof encoding")
	}
	return p, nil
}

func Encode(p Proof) ([]byte, error) {
	if err := p.validate(); err != nil {
		return nil, err
	}
	b, e := json.Marshal(p)
	if len(b) > MaxProofBytes {
		return nil, fmt.Errorf("proof byte bound exceeded")
	}
	return b, e
}
