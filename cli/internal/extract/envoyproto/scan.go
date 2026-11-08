// SPDX-License-Identifier: AGPL-3.0-only

// Package envoyproto reads, from the api/envoy tree of the Envoy repository
// at one pinned commit, the declarations that carry a deprecation marker:
// fields with [deprecated = true], messages and enums with option deprecated
// = true, enum values with [deprecated = true], and the Envoy annotations
// (envoy.annotations.deprecated_at_minor_version and its enum form,
// envoy.annotations.disallowed_by_default). It is a pure text parser: there
// is no protoc, no import resolution, no build and no execution.
//
// Status of the output. The package is inert: nothing in the registry, the
// knowledge data or the factory calls it. Every candidate from Scan is DRAFT:
// a deprecation marker says the field is still accepted, so it can never by
// itself state a removal. Compare of two scans (older, newer) marks a field
// candidate MECHANICAL for exactly one proven case: the newer side declares
// the same message, no longer declares the field name, and reserves both the
// field number and the field name in that message, while the number is not
// used by another field. Everything else stays DRAFT (needs review): a
// message that vanished, a name that vanished without both reservations, a
// renumbered field, a moved or renamed symbol, a message, enum or enum value.
//
// Fail closed. A file the parser does not fully understand, a limit, a
// duplicate symbol, a symlink or submodule entry named *.proto, an option
// value that is not a literal true or false, or a member the shared encoder
// refuses, goes into the ledger and makes the scan incomplete. Compare states
// nothing mechanical when either side is incomplete. Comments never
// contribute: the word "deprecated" in a comment, a string literal or a
// block comment is not a marker. A block comment between a hide marker and
// its declaration does not break the marker's reach, and a marker inside a
// block comment counts as a marker. The only comment convention read is
// "// [#not-implemented-hide:" in the comment-only lines directly above a
// declaration; the declaration (and what it contains) is then not a
// candidate. A hidden field still counts as declared when Compare asks
// whether a name is still present.
//
// Members. A candidate is named by the fully qualified proto name
// (pkg.Message.field, pkg.Message.Nested.field, pkg.Enum.VALUE) encoded with
// membercode.ConfigKey over one property segment per dotted name part. The
// shared encoder has no form specific to protobuf symbols; ConfigKey is the
// existing dotted form and refuses reserved or illegal segments, which then
// go to the ledger.
//
// Wiring blockers. This output must not be wired into the registry, the
// knowledge data or the factory until all of these are done:
//   - a distinct protobuf member form in membercode (a config key and a proto
//     symbol must not share one encoding; needs-audit);
//   - a bump of ResultSchema to v2 together with that member form;
//   - a consumer that binds older and newer to two release tags, ordered by
//     the semver order of extract.TagSource, because Compare trusts the caller
//     for the order of its arguments.
//
// JSON names. Envoy loads configuration through the protobuf JSON mapping,
// which accepts both the proto name and the json_name of a field. Compare
// therefore refuses MECHANICAL when any field of the newer message (hidden or
// not) still accepts a JSON name the removed field accepted: its own name or
// json_name, or the lowerCamel form of its name. A file without a package
// statement is withheld (ENVOY_PACKAGE).
//
// Not read: deprecated_at_minor_version written as a bare option name (it is
// only valid as the parenthesised extension), runtime_features.cc, and enum
// value removal by reservation (enum values stay DRAFT).
package envoyproto

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract"
	"github.com/prufyx/prufyx/cli/internal/extract/membercode"
)

// ResultSchema identifies the canonical JSON of a Result.
const ResultSchema = "prufyx.io/envoy-proto-scan/v1"

// Root is the scanned tree.
const Root = "api/envoy"

// Candidate statuses.
const (
	StatusDraft      = "DRAFT"
	StatusMechanical = "MECHANICAL"
)

// ProofReservedNumberAndName is the only proof that makes a removal
// mechanical.
const ProofReservedNumberAndName = "RESERVED_NUMBER_AND_NAME"

// Candidate kinds.
const (
	KindField     = "field"
	KindMessage   = "message"
	KindEnum      = "enum"
	KindEnumValue = "enum_value"
)

// Candidate is one deprecated declaration.
type Candidate struct {
	Member              string `json:"member"`
	Kind                string `json:"kind"`
	Status              string `json:"status"`
	Proof               string `json:"proof,omitempty"`
	File                string `json:"file"`
	DeprecatedAtMinor   string `json:"deprecated_at_minor_version,omitempty"`
	DisallowedByDefault bool   `json:"disallowed_by_default,omitempty"`
	Number              int64  `json:"number,omitempty"`

	// msg and field are the symbol names the scan itself saw (not parsed back
	// out of Member); only Scan sets them, and Compare reads them.
	msg, field string
}

// Result is the scan of one commit.
type Result struct {
	Schema     string        `json:"schema"`
	Repo       string        `json:"repo"`
	Commit     string        `json:"commit"`
	Files      int           `json:"files"`
	Hidden     int           `json:"hidden"`
	Candidates []Candidate   `json:"candidates"`
	Ledger     []LedgerEntry `json:"ledger"`

	syms map[string]*symbol
}

// Attestable is true only for a scan with an empty ledger.
func (r Result) Attestable() bool { return r.syms != nil && len(r.Ledger) == 0 }

type limits struct {
	dirs      int
	depth     int
	files     int
	fileBytes int
	total     int
	items     int
	nest      int
}

func defaultLimits() limits {
	return limits{dirs: 2048, depth: 16, files: 8192, fileBytes: 1 << 20, total: 64 << 20, items: 500000, nest: 16}
}

// Scan reads Root at commit.
func Scan(r extract.PinnedReader, repo extract.RepoRef, commit string) (Result, error) {
	return scan(r, repo, commit, defaultLimits())
}

func scan(r extract.PinnedReader, repo extract.RepoRef, commit string, lim limits) (Result, error) {
	if !extract.IsCommitSHA(commit) {
		return Result{}, errors.New("envoyproto: commit must be a full lowercase 40-character SHA")
	}
	res := Result{Schema: ResultSchema, Repo: repo.Key, Commit: commit, Candidates: []Candidate{}, syms: map[string]*symbol{}}
	var led []LedgerEntry
	fault := func(code, item string) { led = append(led, LedgerEntry{Code: code, Item: item}) }

	type dirAt struct {
		path  string
		depth int
	}
	var files []string
	queue := []dirAt{{Root, 0}}
	dirs := 0
	limited := false
	for len(queue) > 0 && !limited {
		d := queue[0]
		queue = queue[1:]
		dirs++
		if dirs > lim.dirs || d.depth > lim.depth {
			fault(ReasonLimit, "directories")
			limited = true
			break
		}
		entries, err := r.List(repo, commit, d.path)
		if errors.Is(err, extract.ErrNotFound) {
			if d.path == Root {
				fault(ReasonRootNotFound, Root)
			} else {
				fault(ReasonNotRegular, d.path)
			}
			continue
		}
		if err != nil {
			return Result{}, fmt.Errorf("envoyproto: list %s: %w", d.path, err)
		}
		sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
		for _, e := range entries {
			if !strings.HasPrefix(e.Path, d.path+"/") {
				fault(ReasonNotRegular, d.path)
				continue
			}
			switch {
			case e.Type == "tree":
				queue = append(queue, dirAt{e.Path, d.depth + 1})
			case strings.HasSuffix(e.Path, ".proto"):
				if e.Type != "blob" || (e.Mode != "100644" && e.Mode != "100755") {
					fault(ReasonNotRegular, e.Path)
					continue
				}
				files = append(files, e.Path)
				if len(files) > lim.files {
					fault(ReasonLimit, "files")
					limited = true
				}
			case e.Type == "commit":
				fault(ReasonNotRegular, e.Path)
			}
			if limited {
				break
			}
		}
	}
	sort.Strings(files)
	items := 0
	total := 0
	for _, f := range files {
		if limited {
			break
		}
		data, err := r.Read(repo, commit, f)
		if errors.Is(err, extract.ErrNotFound) {
			fault(ReasonNotRegular, f)
			continue
		}
		if err != nil {
			return Result{}, fmt.Errorf("envoyproto: read %s: %w", f, err)
		}
		if len(data) > lim.fileBytes {
			fault(ReasonFileTooLarge, f)
			continue
		}
		total += len(data)
		if total > lim.total {
			fault(ReasonLimit, "total-bytes")
			limited = true
			break
		}
		res.Files++
		p, err := parseProto(f, data, lim.nest, lim.items-items)
		if err != nil {
			var pf *parseFault
			if errors.As(err, &pf) {
				switch pf.kind {
				case faultLimit:
					fault(ReasonLimit, f)
					limited = true
				case faultPackage:
					fault(ReasonPackage, f)
				case faultOption:
					fault(ReasonOptionValue, fmt.Sprintf("%s:%d", f, pf.line))
				default:
					fault(ReasonParse, fmt.Sprintf("%s:%d", f, pf.line))
				}
			} else {
				fault(ReasonParse, f)
			}
			continue
		}
		items += p.items
		for _, s := range p.syms {
			if _, dup := res.syms[s.full]; dup {
				fault(ReasonDuplicate, s.full)
				continue
			}
			res.syms[s.full] = s
		}
	}

	names := make([]string, 0, len(res.syms))
	for n := range res.syms {
		names = append(names, n)
	}
	sort.Strings(names)
	add := func(msg, fieldName, kind, file, atMinor string, disallowed bool, number int64) {
		full := msg
		if fieldName != "" {
			full = msg + "." + fieldName
		}
		m, err := member(full)
		if err != nil {
			switch {
			case errors.Is(err, membercode.ErrTooLong):
				fault(ReasonMemberLong, itemOf(full))
			case errors.Is(err, membercode.ErrCharset):
				fault(ReasonMemberCharset, itemOf(full))
			case errors.Is(err, membercode.ErrAmbiguous):
				fault(ReasonMemberInvalid, itemOf(full))
			default:
				fault(ReasonMemberInvalid, itemOf(full))
			}
			return
		}
		res.Candidates = append(res.Candidates, Candidate{Member: m, Kind: kind, Status: StatusDraft, File: file,
			DeprecatedAtMinor: atMinor, DisallowedByDefault: disallowed, Number: number, msg: msg, field: fieldName})
	}
	for _, n := range names {
		s := res.syms[n]
		if s.hidden {
			res.Hidden++
		} else if s.deprecated {
			kind := KindMessage
			if s.isEnum {
				kind = KindEnum
			}
			add(s.full, "", kind, s.file, "", false, 0)
		}
		fn := make([]string, 0, len(s.fields))
		for k := range s.fields {
			fn = append(fn, k)
		}
		sort.Strings(fn)
		for _, k := range fn {
			f := s.fields[k]
			switch {
			case f.hidden:
				res.Hidden++
			case f.deprecated || f.atMinor != "":
				add(s.full, f.name, KindField, f.file, f.atMinor, f.disallowed, f.number)
			}
		}
		vn := make([]string, 0, len(s.values))
		for k := range s.values {
			vn = append(vn, k)
		}
		sort.Strings(vn)
		for _, k := range vn {
			v := s.values[k]
			switch {
			case v.hidden:
				res.Hidden++
			case v.deprecated || v.atMinor != "":
				add(s.full, v.name, KindEnumValue, s.file, v.atMinor, false, 0)
			}
		}
	}
	sort.Slice(res.Candidates, func(i, j int) bool {
		if res.Candidates[i].Member != res.Candidates[j].Member {
			return res.Candidates[i].Member < res.Candidates[j].Member
		}
		return res.Candidates[i].Kind < res.Candidates[j].Kind
	})
	res.Ledger = ledgerOf(led)
	return res, nil
}

func itemOf(full string) string {
	if len(full) > MaxLedgerItemLen {
		return "symbol"
	}
	return full
}

// member encodes a fully qualified symbol name.
func member(full string) (string, error) {
	var path []membercode.Seg
	for _, part := range strings.Split(full, ".") {
		path = append(path, membercode.Seg{Kind: membercode.Prop, Name: part})
	}
	return membercode.ConfigKey(path)
}
