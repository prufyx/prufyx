// SPDX-License-Identifier: AGPL-3.0-only

package installsurfaceproof

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"time"
)

// Unavailable identifies a required capability or independently anchored input.
// It must not be interpreted as a successful decision or signing permission.
type Unavailable struct{ Requirement string }

func (e *Unavailable) Error() string { return "install surface unavailable: " + e.Requirement }

// Association is a reviewed immutable input association, supplied separately
// from the producer proof. An input digest carried inside the proof cannot add
// an entry here. Authenticating these entries against BASE is a caller boundary;
// this package supplies neither a live trust resolver nor policy installation.
type Association struct{ CaseID, InputDigest string }
type BasePolicy struct {
	Commit, Tree      string
	Associations      []Association
	MaxObservationAge time.Duration
}

type MaterializedFile struct {
	Mode, GitBlob string
	Bytes         []byte
}

// Materials must be produced by a complete independent source/archive reader,
// not assembled by trusting the proposed inventory. The adapter must authenticate
// the selected index/archive/app association and source Git tree, reject unsafe
// archive entries, and preserve the full retained bytes. No adapter ships here.
type Materials struct {
	Index, Archive, ProducedOutput []byte
	// Observations belong to the independently authenticated capture, not
	// the producer's writable timestamps. Absent observations refuse.
	ObservedAt, ExpiresAt     time.Time
	ArchiveFiles, SourceFiles map[string]MaterializedFile
	Values                    map[string][]byte
	Dependencies              map[string][]byte
}

type Materializer interface {
	Materialize(context.Context, Proof) (Materials, error)
	// Inspect extracts the entire resource and CRD inventory from rerendered
	// bytes independently of the proposed output fields. Missing support refuses.
	Inspect(context.Context, []byte) (Output, error)
}

// Renderer must be an independently approved pinned isolated implementation.
// A fixture implementation proves only this interface, never actual rendering
// capability, source authenticity, consumer integration or deployment support.
type Renderer interface {
	Identity() (binaryDigest, imageDigest, version string)
	Render(context.Context, Render, Materials) ([]byte, error)
}

// ReplayCheck records only a completed replay under the supplied trusted
// dependencies. It is not a signature, admission result or promotion authority.
type ReplayCheck struct{ CaseID, PublicPath, RenderedDigest string }

// InputDigest binds the entire source/dependency/render input statement, excluding
// the proposed output. It is an identity, not an authentication mechanism.
func InputDigest(p Proof) string {
	p.Output = Output{}
	// The immutable association pins identities and complete render inputs;
	// observation freshness is checked separately under authenticated policy.
	p.Origin.ObservedAt = ""
	p.Origin.ExpiresAt = ""
	raw, _ := json.Marshal(p)
	return Digest(append([]byte(Schema+"/inputs\x00"), raw...))
}

func anchored(policy BasePolicy, p Proof) error {
	if !objectRE.MatchString(policy.Commit) || !objectRE.MatchString(policy.Tree) || len(policy.Associations) == 0 || policy.MaxObservationAge <= 0 || policy.MaxObservationAge > 24*time.Hour {
		return &Unavailable{"authenticated BASE association and freshness policy"}
	}
	id, err := p.Tuple.CaseID()
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	found := false
	for _, a := range policy.Associations {
		if len(a.CaseID) != 64 || !digestRE.MatchString("sha256:"+a.CaseID) || !digestRE.MatchString(a.InputDigest) || seen[a.CaseID] {
			return errors.New("invalid or duplicate BASE association")
		}
		seen[a.CaseID] = true
		if a.CaseID == id {
			if a.InputDigest != InputDigest(p) {
				return errors.New("input statement differs from independent BASE association")
			}
			found = true
		}
	}
	if !found {
		return &Unavailable{"source/app/archive association"}
	}
	return nil
}

func checkFiles(inventory []File, files map[string]MaterializedFile) error {
	if len(files) != len(inventory) {
		return errors.New("incomplete or extra materialized inventory")
	}
	for _, f := range inventory {
		actual, ok := files[f.Path]
		if !ok || actual.Mode != f.Mode || actual.GitBlob != f.GitBlob || int64(len(actual.Bytes)) != f.Size || Digest(actual.Bytes) != f.Digest {
			return fmt.Errorf("retained file differs: %s", f.Path)
		}
	}
	return nil
}

// CheckReplay checks exactly one independently requested tuple and its complete
// dependency closure. No proof may choose its own policy, tuple or artifact path.
// Missing real integrations must remain unavailable in admission, O6 and QA.
func CheckReplay(ctx context.Context, raw []byte, want Tuple, policy BasePolicy, reader Materializer, renderer Renderer, now time.Time) (ReplayCheck, error) {
	return checkReplay(ctx, raw, want, policy, reader, renderer, now, 0, map[string]bool{})
}

func checkReplay(ctx context.Context, raw []byte, want Tuple, policy BasePolicy, reader Materializer, renderer Renderer, now time.Time, depth int, active map[string]bool) (ReplayCheck, error) {
	var result ReplayCheck
	if depth > MaxDependencyDepth {
		return result, errors.New("dependency recursion bound exceeded")
	}
	if err := ctx.Err(); err != nil {
		return result, err
	}
	p, err := Decode(raw)
	if err != nil {
		return result, err
	}
	if !reflect.DeepEqual(p.Tuple, want) {
		return result, errors.New("proof tuple differs from independently requested scope")
	}
	if err := anchored(policy, p); err != nil {
		return result, err
	}
	id, _ := want.CaseID()
	if active[id] {
		return result, errors.New("dependency cycle")
	}
	active[id] = true
	defer delete(active, id)
	observed, _ := time.Parse(time.RFC3339, p.Origin.ObservedAt)
	expires, _ := time.Parse(time.RFC3339, p.Origin.ExpiresAt)
	if now.IsZero() || now.Before(observed) || !now.Before(expires) || now.Sub(observed) > policy.MaxObservationAge || expires.Sub(observed) > policy.MaxObservationAge {
		return result, errors.New("observation is future or expired")
	}
	if reader == nil {
		return result, &Unavailable{"complete retained-input materializer"}
	}
	if renderer == nil {
		return result, &Unavailable{"approved isolated renderer"}
	}
	m, err := reader.Materialize(ctx, p)
	if err != nil {
		return result, err
	}
	if m.ObservedAt.IsZero() || m.ExpiresAt.IsZero() || !m.ObservedAt.Equal(observed) || !m.ExpiresAt.Equal(expires) {
		return result, errors.New("producer observation differs from authenticated capture")
	}
	if len(m.Index) == 0 || len(m.Index) > MaxProofBytes || len(m.Archive) == 0 || len(m.Archive) > MaxArchiveBytes || len(m.ProducedOutput) > MaxRenderedBytes || Digest(m.Index) != p.Origin.IndexDigest || Digest(m.Archive) != p.Origin.ArchiveDigest || Digest(m.ProducedOutput) != p.Output.Digest {
		return result, errors.New("retained artifact missing, oversized or digest mismatch")
	}
	if err := checkFiles(p.ArchiveInventory, m.ArchiveFiles); err != nil {
		return result, err
	}
	if err := checkFiles(p.SourceInventory, m.SourceFiles); err != nil {
		return result, err
	}
	lock := Digest(nil)
	if f, ok := m.ArchiveFiles["Chart.lock"]; ok {
		lock = Digest(f.Bytes)
	}
	if lock != p.ChartLockDigest {
		return result, errors.New("retained Chart.lock differs")
	}
	// The reviewed metadata exception is not implemented here. Formatting-only
	// Chart.yaml differences remain unavailable rather than weakening equality.
	if len(m.ArchiveFiles) != len(m.SourceFiles) {
		return result, errors.New("source/archive path set differs")
	}
	for name, a := range m.ArchiveFiles {
		s, ok := m.SourceFiles[name]
		if !ok || a.Mode != s.Mode {
			return result, errors.New("source/archive path or mode differs")
		}
		if !bytes.Equal(a.Bytes, s.Bytes) {
			if name == "Chart.yaml" {
				return result, &Unavailable{"strict typed Chart.yaml comparator"}
			}
			return result, errors.New("source/archive file differs")
		}
	}
	if len(m.Values) != len(p.Render.Values) {
		return result, errors.New("incomplete values artifacts")
	}
	valuesBytes := 0
	for _, a := range p.Render.Values {
		data, ok := m.Values[a.Path]
		valuesBytes += len(data)
		if !ok || valuesBytes > MaxValuesBytes || Digest(data) != a.Digest {
			return result, errors.New("values bytes missing, oversized or mismatched")
		}
	}
	if len(m.Dependencies) != len(p.Dependencies) {
		return result, errors.New("incomplete dependency proof set")
	}
	for _, dep := range p.Dependencies {
		data, ok := m.Dependencies[dep.CaseID]
		if !ok || Digest(data) != dep.ProofDigest {
			return result, errors.New("dependency proof missing or mismatched")
		}
		child, e := Decode(data)
		if e != nil {
			return result, e
		}
		childID, _ := child.Tuple.CaseID()
		if childID != dep.CaseID || dep.Depth != depth+1 {
			return result, errors.New("dependency identity or depth differs")
		}
		if dep.Enabled {
			if _, e := checkReplay(ctx, data, child.Tuple, policy, reader, renderer, now, depth+1, active); e != nil {
				return result, e
			}
		}
	}
	bin, image, version := renderer.Identity()
	if bin != p.Render.BinaryDigest || image != p.Render.ImageDigest || version != p.Render.Version {
		return result, errors.New("renderer identity drift")
	}
	renderCtx, cancel := context.WithTimeout(ctx, time.Duration(p.Render.TimeoutSeconds)*time.Second)
	defer cancel()
	regenerated, err := renderer.Render(renderCtx, p.Render, m)
	if err != nil {
		return result, err
	}
	if err := renderCtx.Err(); err != nil {
		return result, err
	}
	if len(regenerated) > MaxRenderedBytes || !bytes.Equal(regenerated, m.ProducedOutput) {
		return result, errors.New("independent rerender differs from proposed output")
	}
	actual, err := reader.Inspect(renderCtx, regenerated)
	if err != nil {
		return result, err
	}
	if actual.Digest != Digest(regenerated) || !reflect.DeepEqual(actual, p.Output) {
		return result, errors.New("independent output/CRD extraction differs")
	}
	result.CaseID = id
	result.PublicPath, _ = want.PublicPath()
	result.RenderedDigest = Digest(regenerated)
	if !strings.HasSuffix(result.PublicPath, ".json") {
		return ReplayCheck{}, errors.New("invalid derived path")
	}
	return result, nil
}
