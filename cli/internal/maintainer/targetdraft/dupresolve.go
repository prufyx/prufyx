// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Duplicate-definition resolution (opt-in, Input.DeriveDuplicates).
//
// When the only thing that stops a plain run is that several files define the
// same group and kind, and every copy has the same full decoded spec at every
// tag, one copy is enough. The choice is expressed as an exact-file list of
// the files that stay (the generator's positive installPaths machinery); no
// exclusion is created and the target file gets no new field. Anything this
// file cannot prove equal is a typed stop. The module is pure: no IO.

// Fixed texts of every derived entry.
const (
	derivedReason       = "derived: duplicate-crd single source"
	derivedEvidenceNone = "derived: file defines no duplicated definition"
)

// canonSpec writes the canonical structural encoding of a decoded YAML value:
// maps by sorted key, every scalar with its decoded type. Nothing is
// normalised (no default filling, no int/float/string unification); any value
// of an unexpected type is an error, which the caller treats as not equal.
func canonSpec(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("n;")
	case bool:
		b.WriteString("b:" + strconv.FormatBool(x) + ";")
	case int:
		b.WriteString("i:" + strconv.FormatInt(int64(x), 10) + ";")
	case int64:
		b.WriteString("i:" + strconv.FormatInt(x, 10) + ";")
	case uint64:
		b.WriteString("u:" + strconv.FormatUint(x, 10) + ";")
	case float64:
		b.WriteString("f:" + strconv.FormatFloat(x, 'g', -1, 64) + ";")
	case string:
		b.WriteString("s:" + strconv.Quote(x) + ";")
	case []any:
		b.WriteString("[")
		for _, e := range x {
			if err := canonSpec(b, e); err != nil {
				return err
			}
		}
		b.WriteString("]")
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("{")
		for _, k := range keys {
			b.WriteString("k:" + strconv.Quote(k) + "=")
			if err := canonSpec(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteString("}")
	default:
		return fmt.Errorf("unsupported value type %T", v)
	}
	return nil
}

func sumHex(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// specDigest returns the digest of a definition (apiVersion and the whole
// spec) and the digest of each top-level part. Empty digest: not computable,
// never equal to anything.
func specDigest(apiVersion, spec any) (string, map[string]string) {
	m, ok := spec.(map[string]any)
	if !ok {
		return "", nil
	}
	parts := map[string]string{}
	var ab bytes.Buffer
	if err := canonSpec(&ab, apiVersion); err != nil {
		return "", nil
	}
	parts["apiVersion"] = sumHex(ab.Bytes())
	for k, v := range m {
		var pb bytes.Buffer
		if err := canonSpec(&pb, v); err != nil {
			return "", nil
		}
		parts["spec."+k] = sumHex(pb.Bytes())
	}
	names := make([]string, 0, len(parts))
	for k := range parts {
		names = append(names, k)
	}
	sort.Strings(names)
	var all bytes.Buffer
	for _, k := range names {
		all.WriteString(strconv.Quote(k) + "=" + parts[k] + "\n")
	}
	return sumHex(all.Bytes()), parts
}

// firstDifference names the first top-level part (sorted) in which two
// definitions differ, or says that a digest is missing.
func firstDifference(a, b crd) string {
	if a.SpecDigest == "" || b.SpecDigest == "" {
		return "spec digest not computable"
	}
	set := map[string]bool{}
	for k := range a.SpecParts {
		set[k] = true
	}
	for k := range b.SpecParts {
		set[k] = true
	}
	var ks []string
	for k := range set {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		if a.SpecParts[k] != b.SpecParts[k] {
			return k
		}
	}
	return "unknown"
}

// crdsEqual is the comparator: both full-spec digests exist and are identical.
// It is a single function so a test can prove that weakening it is caught.
var crdsEqual = func(a, b crd) bool {
	return a.SpecDigest != "" && a.SpecDigest == b.SpecDigest
}

// Rank classes of a copy, lower wins. The table is a literal, pinned by a test
// and never read from repository content. The choice among byte-equal copies
// is non-semantic; it only has to be deterministic.
const (
	rankPlainDir = 0 // a plain directory of definitions
	rankChart    = 1 // chart crds/ or files/
	rankTemplate = 2 // chart templates/
	rankBundle   = 3 // bundle / OLM
)

func rankClass(p string) int {
	segs := strings.Split(p, "/")
	dirs := segs[:len(segs)-1]
	has := func(names ...string) bool {
		for _, d := range dirs {
			for _, n := range names {
				if d == n {
					return true
				}
			}
		}
		return false
	}
	switch {
	case has("bundle", "bundles", "olm", "olm-catalog", "manifests"):
		return rankBundle
	case has("templates"):
		return rankTemplate
	case has("charts", "chart", "helm", "files"):
		return rankChart
	}
	return rankPlainDir
}

// tagFiles is the plain-pass reading of one tag: the files that pass read.
type tagFiles struct {
	Tag      string
	Included map[string]*inclusion
}

// derivedSource is one duplicated definition resolved to one source.
type derivedSource struct {
	Key     string
	Kept    string
	Dropped []string
	Digest  string   // spec digest at the newest tag
	Tags    []string // tags where every copy was compared and found equal
}

// derivation is the pure result of resolveDuplicates.
type derivation struct {
	Rules   []InstallPathRule // exact files that stay, sorted by path
	Dropped []string          // exact files dropped as duplicate copies, sorted
	Sources []derivedSource   // one per duplicated key, sorted by key
}

type occurrence struct {
	path  string
	c     crd
	multi bool
}

func crdKey(c crd) string { return c.Group + "/" + c.Kind }

func occurrences(f tagFiles) map[string][]occurrence {
	out := map[string][]occurrence{}
	var paths []string
	for p := range f.Included {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		inc := f.Included[p]
		for _, c := range inc.CRDs {
			out[crdKey(c)] = append(out[crdKey(c)], occurrence{path: p, c: c, multi: len(inc.CRDs) > 1})
		}
	}
	return out
}

// rankLess orders candidate sources: single-definition files before
// multi-definition files, then the class rank, then the path.
func rankLess(a, b occurrence) bool {
	if a.multi != b.multi {
		return !a.multi
	}
	if ca, cb := rankClass(a.path), rankClass(b.path); ca != cb {
		return ca < cb
	}
	return a.path < b.path
}

// resolveDuplicates derives the single-source list from the plain-pass
// reading of every tag (oldest first, the newest last). It returns the
// derivation (nil when none can be made at the newest tag) and the stops per
// tag; a tag with stops is treated as unreadable by the window logic and the
// newest tag with stops ends the run. It never decides anything from the
// repository beyond the decoded definitions.
func resolveDuplicates(tags []tagFiles) (*derivation, [][]Stop) {
	stops := make([][]Stop, len(tags))
	if len(tags) == 0 {
		return nil, stops
	}
	last := len(tags) - 1
	add := func(i int, code, subject, detail string) {
		stops[i] = append(stops[i], stop(code, subject, detail))
	}
	newest := occurrences(tags[last])

	// Choose one source per key duplicated at the newest tag.
	var keys []string
	for k, occ := range newest {
		if len(occ) > 1 {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	if len(keys) == 0 {
		add(last, StopDuplicateCRDUnresolvable, "", "no duplicated definition at the newest tag")
		return nil, stops
	}
	kept := map[string]string{}  // key -> chosen path
	losers := map[string]bool{}  // paths that lost for some key
	winners := map[string]bool{} // paths chosen for some key
	droppedBy := map[string][]string{}
	bad := false
	for _, k := range keys {
		occ := newest[k]
		seen := map[string]bool{}
		for _, o := range occ {
			if seen[o.path] {
				add(last, StopDuplicateCRDUnresolvable, k, o.path+" defines it twice")
				bad = true
			}
			seen[o.path] = true
		}
		best := occ[0]
		for _, o := range occ[1:] {
			if rankLess(o, best) {
				best = o
			}
		}
		kept[k] = best.path
		winners[best.path] = true
		for _, o := range occ {
			if o.path != best.path {
				losers[o.path] = true
				droppedBy[k] = append(droppedBy[k], o.path)
			}
		}
	}
	for p := range losers {
		if winners[p] {
			add(last, StopDuplicateCRDUnresolvable, p, "the file is the chosen source of one definition and a dropped copy of another")
			bad = true
		}
	}
	if bad {
		return nil, stops
	}

	d := &derivation{}
	for p := range losers {
		d.Dropped = append(d.Dropped, p)
	}
	sort.Strings(d.Dropped)
	dropped := map[string]bool{}
	for _, p := range d.Dropped {
		dropped[p] = true
	}
	var keptPaths []string
	for p := range tags[last].Included {
		if !dropped[p] {
			keptPaths = append(keptPaths, p)
		}
	}
	sort.Strings(keptPaths)
	keptSet := map[string]bool{}
	for _, p := range keptPaths {
		keptSet[p] = true
	}
	digestsOf := map[string][]string{}
	for _, k := range keys {
		for _, o := range newest[k] {
			if o.path == kept[k] {
				digestsOf[o.path] = append(digestsOf[o.path], k+"="+o.c.SpecDigest)
			}
		}
	}
	for _, p := range keptPaths {
		ev := derivedEvidenceNone
		if ds := digestsOf[p]; len(ds) > 0 {
			sort.Strings(ds)
			ev = "derived: spec digests at the newest tag " + strings.Join(ds, ",")
		}
		d.Rules = append(d.Rules, InstallPathRule{Path: p, Reason: derivedReason, Evidence: ev})
	}

	srcs := map[string]*derivedSource{}
	for _, k := range keys {
		ds := droppedBy[k]
		sort.Strings(ds)
		var dig string
		for _, o := range newest[k] {
			if o.path == kept[k] {
				dig = o.c.SpecDigest
			}
		}
		srcs[k] = &derivedSource{Key: k, Kept: kept[k], Dropped: ds, Digest: dig}
	}

	// Verify every tag against the chosen sources, fully and independently of
	// how the choice was made.
	for i, tf := range tags {
		occ := occurrences(tf)
		// Plain-pass files other than the kept list at this tag.
		for p := range tf.Included {
			if !dropped[p] && !keptSet[p] {
				add(i, StopDuplicateCRDUnresolvable, p, "file read by the plain pass at "+tf.Tag+" is not in the derived source list")
			}
		}
		var okeys []string
		for k := range occ {
			okeys = append(okeys, k)
		}
		sort.Strings(okeys)
		for _, k := range okeys {
			oc := occ[k]
			// Same-file repeat, and equality of every copy.
			seen := map[string]bool{}
			for _, o := range oc {
				if seen[o.path] {
					add(i, StopDuplicateCRDUnresolvable, k, o.path+" defines it twice at "+tf.Tag)
				}
				seen[o.path] = true
			}
			equalAll := true
			for _, o := range oc[1:] {
				if !crdsEqual(oc[0].c, o.c) {
					add(i, StopDuplicateCRDDiffers, k, fmt.Sprintf("%s and %s differ at %s in %s", oc[0].path, o.path, tf.Tag, firstDifference(oc[0].c, o.c)))
					equalAll = false
					break
				}
			}
			// Kept holders of the key at this tag.
			var holders []occurrence
			for _, o := range oc {
				if !dropped[o.path] {
					holders = append(holders, o)
				}
			}
			anyDropped := len(holders) != len(oc)
			if len(holders) > 1 {
				add(i, StopDuplicateCRDUnresolvable, k, "more than one kept source holds it at "+tf.Tag)
				continue
			}
			if !anyDropped {
				continue
			}
			if len(holders) == 0 {
				code := StopDuplicateCRDUnresolvable
				if _, chosen := kept[k]; chosen {
					code = StopDuplicateCRDNoCommonSource
				}
				add(i, code, k, "no kept source holds it at "+tf.Tag+" although "+oc[0].path+" does")
				continue
			}
			for _, o := range oc {
				if dropped[o.path] && !crdsEqual(holders[0].c, o.c) && equalAll {
					add(i, StopDuplicateCRDDiffers, k, fmt.Sprintf("%s and %s differ at %s in %s", holders[0].path, o.path, tf.Tag, firstDifference(holders[0].c, o.c)))
				}
			}
			if s, ok := srcs[k]; ok && equalAll && len(oc) > 1 {
				s.Tags = append(s.Tags, tf.Tag)
			}
		}
		// The kept source of every derived key must exist at the tag where
		// any copy exists (covered above); a derived key that no copy holds at
		// this tag is simply absent.
	}
	for _, k := range keys {
		d.Sources = append(d.Sources, *srcs[k])
	}
	return d, stops
}

// droppedInside reports whether any dropped copy lies below the directory
// (prefix ending in "/"). A directory that contains a dropped copy must never
// be collapsed into a directory entry, because the entry would silently read
// the dropped copy again; collapseDirsDropping calls this for every candidate
// directory and refuses the collapse when it returns true.
func droppedInside(dir string, dropped []string) bool {
	if !strings.HasSuffix(dir, "/") {
		dir += "/"
	}
	for _, p := range dropped {
		if strings.HasPrefix(p, dir) {
			return true
		}
	}
	return false
}
