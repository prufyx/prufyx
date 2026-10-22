// SPDX-License-Identifier: AGPL-3.0-only

// Package servedlists derives the served-API list of a Kubernetes minor line
// from the OpenAPI specification (api/openapi-spec/swagger.json) at the
// line's v<line>.0 release tag. The knowledge gate runs the same functions
// to re-derive a list before it admits one, so a list is only ever the
// output of this code over pinned upstream bytes.
//
// The specification is generated with every API group version on, beta and
// alpha ones that a default build does not serve included. The list therefore
// names stable versions only (^v[0-9]+$) and is marked partial: a pair absent
// from it is not reviewed, never known to be unserved.
//
// A pair is listed when the specification has a create (POST) operation on a
// collection path or a replace (PUT) operation on an object path for it:
// subresources, watch paths and every other verb are left out.
package servedlists

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prufyx/prufyx/cli/internal/constraintengine"
	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
	"github.com/prufyx/prufyx/cli/internal/strictjson"
)

// Identity of the deriver. It is not an extract.Extractor (a list is per
// line, not per version pair) and is not in the extractor catalog.
const (
	ID      = "k8s.served-api-list"
	Version = "1.0.0"
	// SourceDir is this package's directory under the module's internal/.
	SourceDir = "servedlists"
)

//go:embed *.go
var source embed.FS

// Upstream coordinates.
const (
	Repo        = "github.com/kubernetes/kubernetes"
	SwaggerPath = "api/openapi-spec/swagger.json"
)

// Limits.
const (
	// MaxSwaggerBytes bounds the specification read (about 4-6 MiB today).
	MaxSwaggerBytes = 32 << 20
	maxPaths        = 100000
)

// Lease is how long a derived list stays valid: the longest window a record
// may carry less one day, so the record stays valid with a margin.
const Lease = lineattest.MaxWindow - 24*time.Hour

var (
	versionRE = regexp.MustCompile(`^v[0-9]+$`)
	lineRE    = regexp.MustCompile(`^1\.(0|[1-9][0-9]{0,3})$`)
)

var (
	identityOnce sync.Once
	identity     constraintengine.Extractor
	identityErr  error
)

// Identity is the identity of this deriver: its id, version and the code
// digest over its own source and the source of the served-list record format
// (internal/servedapis). The extract framework is not part of it.
func Identity() (constraintengine.Extractor, error) {
	identityOnce.Do(func() {
		dir, files := servedapis.SourceFiles()
		code, err := extract.CodeFiles(extract.SourceSet{Dir: SourceDir, Files: source}, extract.SourceSet{Dir: dir, Files: files})
		if err != nil {
			identityErr = fmt.Errorf("code digest of %s: %w", ID, err)
			return
		}
		identity = constraintengine.Extractor{ID: ID, Version: Version, CodeDigest: extract.CodeDigest(code)}
	})
	return identity, identityErr
}

// SourceID is the evidence source ID of the line's specification.
func SourceID(line string) string { return "openapi-v" + line + ".0" }

// ReleaseTag is the release tag whose specification is the line's source.
func ReleaseTag(line string) (string, error) {
	if !lineRE.MatchString(line) {
		return "", fmt.Errorf("line %q is not a Kubernetes 1.N line", line)
	}
	return "v" + line + ".0", nil
}

// ReleaseCommit returns the commit the line's release tag points at. The
// tag must exist exactly once, at a full commit SHA.
func ReleaseCommit(tags []extract.Tag, line string) (string, error) {
	want, err := ReleaseTag(line)
	if err != nil {
		return "", err
	}
	commit := ""
	for _, t := range tags {
		if t.Name != want {
			continue
		}
		if commit != "" && commit != t.Commit {
			return "", fmt.Errorf("tag %s names two commits", want)
		}
		commit = t.Commit
	}
	if commit == "" {
		return "", fmt.Errorf("no tag %s is recorded", want)
	}
	if !extract.IsCommitSHA(commit) {
		return "", fmt.Errorf("tag %s has no pinned commit", want)
	}
	return commit, nil
}

// ReadSwagger reads the specification at commit, bounded in size.
func ReadSwagger(reader extract.PinnedReader, commit string) ([]byte, error) {
	if reader == nil {
		return nil, fmt.Errorf("no upstream source is configured")
	}
	repo, err := extract.ParseRepo(Repo)
	if err != nil {
		return nil, err
	}
	data, err := reader.Read(repo, commit, SwaggerPath)
	if err != nil {
		return nil, fmt.Errorf("read %s at %s: %w", SwaggerPath, commit, err)
	}
	if len(data) == 0 || len(data) > MaxSwaggerBytes {
		return nil, fmt.Errorf("%s at %s is %d bytes, want 1-%d", SwaggerPath, commit, len(data), MaxSwaggerBytes)
	}
	return data, nil
}

// operation is the part of an OpenAPI operation the deriver reads.
type operation struct {
	Action string `json:"x-kubernetes-action"`
	GVK    *struct {
		Group   string `json:"group"`
		Version string `json:"version"`
		Kind    string `json:"kind"`
	} `json:"x-kubernetes-group-version-kind"`
}

// Derive returns the sorted "apiVersion kind" pairs of line from the
// specification bytes. Zero pairs is an error: a specification that yields
// nothing proves nothing. Parsing is strict and bounded.
func Derive(line string, swagger []byte) ([]string, error) {
	if _, err := ReleaseTag(line); err != nil {
		return nil, err
	}
	if len(swagger) == 0 || len(swagger) > MaxSwaggerBytes {
		return nil, fmt.Errorf("specification of %d bytes, want 1-%d", len(swagger), MaxSwaggerBytes)
	}
	if err := strictjson.Check(swagger); err != nil {
		return nil, fmt.Errorf("specification: %w", err)
	}
	var doc struct {
		Swagger string                                `json:"swagger"`
		Paths   map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(swagger, &doc); err != nil {
		return nil, fmt.Errorf("specification: %w", err)
	}
	if doc.Swagger == "" || len(doc.Paths) == 0 || len(doc.Paths) > maxPaths {
		return nil, fmt.Errorf("not a Kubernetes OpenAPI specification with paths (%d)", len(doc.Paths))
	}
	set := map[string]bool{}
	for path, item := range doc.Paths {
		for _, verb := range []string{"post", "put"} {
			raw, ok := item[verb]
			if !ok {
				continue
			}
			var op operation
			if err := json.Unmarshal(raw, &op); err != nil {
				return nil, fmt.Errorf("%s %s: %w", verb, path, err)
			}
			if op.Action != verb || op.GVK == nil || !servedPath(path, verb) {
				continue
			}
			g := op.GVK
			if !versionRE.MatchString(g.Version) {
				continue
			}
			if g.Kind == "" {
				return nil, fmt.Errorf("%s %s: no kind", verb, path)
			}
			if err := pathMatches(path, g.Group, g.Version); err != nil {
				return nil, fmt.Errorf("%s %s: %w", verb, path, err)
			}
			pair := g.Version + " " + g.Kind
			if g.Group != "" {
				pair = g.Group + "/" + pair
			}
			set[pair] = true
		}
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("the specification of line %s yields no served pair", line)
	}
	if len(set) > servedapis.MaxAPIs {
		return nil, fmt.Errorf("the specification of line %s yields %d pairs, above %d", line, len(set), servedapis.MaxAPIs)
	}
	pairs := make([]string, 0, len(set))
	for pair := range set {
		pairs = append(pairs, pair)
	}
	sort.Strings(pairs)
	return pairs, nil
}

// servedPath reports whether a verb on path creates or replaces a whole
// resource: PUT on an object path whose last segment is exactly {name}, POST
// on a collection path whose last segment is no parameter and which is not
// below an object ({name}). Watch paths are never used.
func servedPath(path, verb string) bool {
	if strings.Contains(path, "/watch/") || (!strings.HasPrefix(path, "/api/") && !strings.HasPrefix(path, "/apis/")) {
		return false
	}
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	last := segs[len(segs)-1]
	if last == "" {
		return false
	}
	switch verb {
	case "put":
		return last == "{name}"
	case "post":
		if strings.HasPrefix(last, "{") {
			return false
		}
		return len(segs) < 2 || segs[len(segs)-2] != "{name}"
	}
	return false
}

// pathMatches requires the group and version of an operation to be the ones
// its path names (/api/<version>/... or /apis/<group>/<version>/...).
func pathMatches(path, group, version string) error {
	segs := strings.Split(strings.TrimPrefix(path, "/"), "/")
	switch {
	case segs[0] == "api" && len(segs) > 2:
		if group != "" || segs[1] != version {
			return fmt.Errorf("group/version %q/%q is not the path's", group, version)
		}
	case segs[0] == "apis" && len(segs) > 3:
		if segs[1] != group || segs[2] != version {
			return fmt.Errorf("group/version %q/%q is not the path's", group, version)
		}
	default:
		return fmt.Errorf("path is not an API resource path")
	}
	return nil
}

// Assemble builds the served-list record of line from the specification
// bytes at commit. derivedAt is whole-second UTC; validUntil is after it and
// at most Lease later. The record is marked partial, mechanical, with the
// specification as its only source.
func Assemble(line, commit string, swagger []byte, derivedAt, validUntil time.Time) (servedapis.Record, error) {
	if !extract.IsCommitSHA(commit) {
		return servedapis.Record{}, fmt.Errorf("commit %q is not a full commit SHA", commit)
	}
	derivedAt, validUntil = derivedAt.UTC(), validUntil.UTC()
	if derivedAt.IsZero() || !derivedAt.Equal(derivedAt.Truncate(time.Second)) || !validUntil.Equal(validUntil.Truncate(time.Second)) {
		return servedapis.Record{}, fmt.Errorf("derivedAt and validUntil must be whole seconds")
	}
	if !validUntil.After(derivedAt) || validUntil.Sub(derivedAt) > Lease {
		return servedapis.Record{}, fmt.Errorf("validUntil must be after derivedAt and at most %s later", Lease)
	}
	pairs, err := Derive(line, swagger)
	if err != nil {
		return servedapis.Record{}, err
	}
	x, err := Identity()
	if err != nil {
		return servedapis.Record{}, err
	}
	repo, err := extract.ParseRepo(Repo)
	if err != nil {
		return servedapis.Record{}, err
	}
	at := derivedAt.Format(time.RFC3339)
	rec := servedapis.Record{
		Component: servedapis.KubernetesComponent, Line: line, Completeness: servedapis.CompletenessPartial, APIs: pairs,
		Evidence: lineattest.Evidence{
			Basis: constraintengine.BasisMechanical, Extractor: &x, DerivedAt: at, ReviewedAt: at, ValidUntil: validUntil.Format(time.RFC3339),
			Sources: []constraintengine.SourceEvidence{{
				ID: SourceID(line), URL: repo.BlobURL(commit, SwaggerPath), Revision: commit,
				ContentDigest: SwaggerDigest(swagger), StartLine: 1, EndLine: extract.CountLines(swagger),
			}},
		},
	}
	if err := rec.Validate(); err != nil {
		return servedapis.Record{}, err
	}
	return rec, nil
}

// Build derives the served-list record of line at now: it resolves the
// line's release tag, reads the specification at the tag's commit and
// assembles the record with a lease of Lease.
func Build(ctx context.Context, tags extract.TagSource, reader extract.PinnedReader, line string, now time.Time) (servedapis.Record, error) {
	if tags == nil {
		return servedapis.Record{}, fmt.Errorf("no tag source is configured")
	}
	repo, err := extract.ParseRepo(Repo)
	if err != nil {
		return servedapis.Record{}, err
	}
	if err := ctx.Err(); err != nil {
		return servedapis.Record{}, err
	}
	list, err := tags.Tags(repo)
	if err != nil {
		return servedapis.Record{}, fmt.Errorf("tags of %s: %w", Repo, err)
	}
	commit, err := ReleaseCommit(list, line)
	if err != nil {
		return servedapis.Record{}, err
	}
	if err := ctx.Err(); err != nil {
		return servedapis.Record{}, err
	}
	data, err := ReadSwagger(reader, commit)
	if err != nil {
		return servedapis.Record{}, err
	}
	now = now.UTC()
	return Assemble(line, commit, data, now, now.Add(Lease))
}

// SwaggerDigest is "sha256:" and the hex sha256 of data.
func SwaggerDigest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}
