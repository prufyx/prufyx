// SPDX-License-Identifier: AGPL-3.0-only

package onboardbundle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// MaxBundleBytes caps the sum of all bundle file sizes that seal accepts.
	MaxBundleBytes = 512 * 1024
	// MaxFieldRunes caps any single string (key or value) that seal accepts.
	MaxFieldRunes = 2000
	maxQuoteRunes = 800
)

// maxBundleBytes is MaxBundleBytes; a variable only so a test can lower it.
var maxBundleBytes = MaxBundleBytes

var (
	sealCommitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
	sealTimeRE   = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	slugRE       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)
)

const sealHelp = `usage: prufyx-maintainer onboard-bundle seal [flags] DIR

Writes DIR/receipt.json for a bundle whose other files are already in place.
It computes the per-file sha256 values and bundleSha256 with the same function
"onboard-bundle validate" uses, and edits no other file.

The receipt is an INTEGRITY record only. It binds the bytes of the bundle
files and nothing else: not the repository, the invite, a snapshot or the
tool version. It is not provenance and not a claim that anything is true or
reviewed; it is replayable and anyone can re-seal edited content. Maintainers
re-derive every fact from upstream in review.

DIR must be named after the slug in its project.json. seal refuses a bundle
with any finding other than a stale or missing receipt, a string with a
character outside printable ASCII (quotes excepted), a string over 2000
characters, or more than 512 KiB in all. A receipt that exists and no longer
matches the files is refused unless --force-reseal; the changes are printed.
seal never writes origin, a review result or anything an importer derives.

flags:
  -force-reseal   replace an existing receipt that does not match the files
  -tool-commit    40-hex commit recorded as tool.prufyxCommit (self-declared,
                  unverified); required when DIR has no receipt
  -generated-at   UTC time YYYY-MM-DDTHH:MM:SSZ; required when DIR has no
                  receipt (seal never reads the clock)
`

func runSeal(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("onboard-bundle seal", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	force := fs.Bool("force-reseal", false, "")
	tool := fs.String("tool-commit", "", "")
	gen := fs.String("generated-at", "", "")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, sealHelp)
			return 0
		}
		fmt.Fprintf(stderr, "onboard-bundle seal: %v\n", err)
		fmt.Fprint(stderr, sealHelp)
		return 2
	}
	if fs.NArg() != 1 {
		fmt.Fprint(stderr, sealHelp)
		return 2
	}
	res, err := Seal(fs.Arg(0), SealOptions{ToolCommit: *tool, GeneratedAt: *gen, ForceReseal: *force})
	for _, line := range res.Notes {
		fmt.Fprintln(stdout, line)
	}
	if err != nil {
		fmt.Fprintf(stderr, "onboard-bundle seal: %s: %v\n", fs.Arg(0), err)
		var ue usageError
		if errors.As(err, &ue) {
			return 2
		}
		var re refusal
		if errors.As(err, &re) {
			return 1
		}
		return 2
	}
	return 0
}

type usageError struct{ error }
type refusal struct{ error }

func refuse(format string, a ...any) error { return refusal{fmt.Errorf(format, a...)} }

// SealOptions are the inputs of Seal that are not in the bundle itself.
type SealOptions struct {
	ToolCommit  string // 40-hex, self-declared; required without an existing receipt
	GeneratedAt string // UTC timestamp; required without an existing receipt
	ForceReseal bool
}

// SealResult carries the lines Seal reports (changes, notes).
type SealResult struct{ Notes []string }

// Seal writes dir/receipt.json for the bundle in dir. It is fail-closed: on
// any refusal or error nothing is changed, and a receipt that does not
// validate after the write is rolled back.
func Seal(dir string, o SealOptions) (SealResult, error) {
	var res SealResult
	info, err := os.Lstat(dir)
	if err != nil {
		return res, err
	}
	if !info.IsDir() {
		return res, errors.New("not a directory")
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return res, err
	}
	if o.ToolCommit != "" && !sealCommitRE.MatchString(o.ToolCommit) {
		return res, usageError{errors.New("--tool-commit must be 40 lowercase hex characters")}
	}
	if o.GeneratedAt != "" && !sealTimeRE.MatchString(o.GeneratedAt) {
		return res, usageError{errors.New("--generated-at must look like 2006-01-02T15:04:05Z")}
	}
	findings, err := Validate(abs)
	if err != nil {
		return res, err
	}
	var blocking []string
	for _, f := range findings {
		if isReceiptDigestFinding(f) {
			continue
		}
		blocking = append(blocking, f)
	}
	if len(blocking) > 0 {
		return res, refuse("refused, %d finding(s) other than the receipt digests:\n  %s", len(blocking), strings.Join(blocking, "\n  "))
	}
	// Read every file once; digests and caps use the same bytes.
	files, err := collectFiles(abs, new([]string))
	if err != nil {
		return res, err
	}
	digests := map[string]string{}
	docs := map[string]any{}
	var total int
	for _, rel := range files {
		raw, tooBig, err := readBounded(filepath.Join(abs, filepath.FromSlash(rel)))
		if err != nil {
			return res, err
		}
		if tooBig {
			return res, refuse("%s: over %d bytes", rel, MaxFileBytes)
		}
		doc, err := parseStrict(raw)
		if err != nil {
			return res, refuse("%s: %v", rel, err)
		}
		docs[rel] = doc
		if rel == "receipt.json" {
			continue
		}
		total += len(raw)
		sum := sha256.Sum256(raw)
		digests[rel] = hex.EncodeToString(sum[:])
	}
	if total > maxBundleBytes {
		return res, refuse("bundle files total %d bytes, more than %d", total, maxBundleBytes)
	}
	if bad := fieldFindings(docs); len(bad) > 0 {
		return res, refuse("refused, %d field(s) outside the seal limits:\n  %s", len(bad), strings.Join(bad, "\n  "))
	}
	proj, _ := docs["project.json"].(map[string]any)
	slug, _ := proj["slug"].(string)
	if !slugRE.MatchString(slug) || filepath.Base(abs) != slug {
		return res, refuse("directory name %q must equal the slug in project.json (%q)", filepath.Base(abs), slug)
	}

	old, hadReceipt := docs["receipt.json"].(map[string]any)
	rcpt := map[string]any{}
	want := BundleDigest(digests)
	if hadReceipt {
		changes, fileChanged := receiptChanges(old, digests, want)
		if len(changes) == 0 && len(findings) == 0 {
			res.Notes = append(res.Notes, "receipt already matches the files; nothing written")
			return res, nil
		}
		if !o.ForceReseal {
			res.Notes = append(res.Notes, changes...)
			return res, refuse("existing receipt does not match the files; re-run with --force-reseal to replace it")
		}
		res.Notes = append(res.Notes, changes...)
		for k, v := range old {
			rcpt[k] = v
		}
		if fileChanged {
			// A stale offline-check result must not survive a content change.
			if ck, ok := rcpt["checks"].(map[string]any); ok && ck["targetCheckOffline"] != "not-run" {
				ck2 := map[string]any{}
				for k, v := range ck {
					ck2[k] = v
				}
				ck2["targetCheckOffline"] = "not-run"
				rcpt["checks"] = ck2
				res.Notes = append(res.Notes, "changed: checks.targetCheckOffline reset to not-run (files changed)")
			}
		}
		if o.ToolCommit != "" {
			rcpt["tool"] = map[string]any{"prufyxCommit": o.ToolCommit}
		}
		if o.GeneratedAt != "" {
			rcpt["generatedAt"] = o.GeneratedAt
		}
	} else {
		if o.ToolCommit == "" || o.GeneratedAt == "" {
			return res, usageError{errors.New("no receipt.json: --tool-commit and --generated-at are required")}
		}
		rcpt = map[string]any{
			"schema":      "prufyx.io/onboard-bundle/v1",
			"kind":        "receipt",
			"kit":         "k0-v0",
			"agentLabel":  "maintainer submission",
			"generatedAt": o.GeneratedAt,
			"tool":        map[string]any{"prufyxCommit": o.ToolCommit},
			"review":      map[string]any{"state": "NOT_REVIEWED", "admissionState": "NOT_ADMITTED"},
			"checks":      map[string]any{"targetCheckOffline": "not-run", "extractRun": "not-run", "dropped": []any{}},
		}
		res.Notes = append(res.Notes, "new receipt: tool.prufyxCommit is self-declared and unverified")
	}
	names := make([]string, 0, len(digests))
	for n := range digests {
		names = append(names, n)
	}
	sort.Strings(names)
	list := make([]any, 0, len(names))
	for _, n := range names {
		list = append(list, map[string]any{"name": n, "sha256": digests[n]})
	}
	rcpt["files"] = list
	rcpt["bundleSha256"] = want

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rcpt); err != nil {
		return res, err
	}
	target := filepath.Join(abs, "receipt.json")
	var prev []byte
	if hadReceipt {
		if prev, err = os.ReadFile(target); err != nil {
			return res, err
		}
	}
	tmp, err := os.CreateTemp(abs, ".receipt-*.tmp")
	if err != nil {
		return res, err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if _, err := tmp.Write(buf.Bytes()); err != nil {
		tmp.Close()
		return res, err
	}
	if err := tmp.Chmod(0o644); err != nil {
		tmp.Close()
		return res, err
	}
	if err := tmp.Close(); err != nil {
		return res, err
	}
	if err := os.Rename(tmpName, target); err != nil {
		return res, err
	}
	post, err := Validate(abs)
	if err != nil || len(post) > 0 {
		if hadReceipt {
			_ = os.WriteFile(target, prev, 0o644)
		} else {
			_ = os.Remove(target)
		}
		if err != nil {
			return res, err
		}
		return res, refuse("sealed receipt did not validate, rolled back:\n  %s", strings.Join(post, "\n  "))
	}
	res.Notes = append(res.Notes, "sealed "+target+" (integrity only: binds file bytes, not provenance)")
	return res, nil
}

func isReceiptDigestFinding(f string) bool {
	return f == "receipt.json: missing" ||
		strings.HasPrefix(f, "receipt.json: bundleSha256 does not match the files") ||
		f == "receipt.json: files list does not match the bundle files"
}

// receiptChanges lists, one line each, how the existing receipt differs from
// the digests computed now.
func receiptChanges(old map[string]any, digests map[string]string, want string) ([]string, bool) {
	listed := map[string]string{}
	if fl, ok := old["files"].([]any); ok {
		for _, x := range fl {
			if m, ok := x.(map[string]any); ok {
				n, _ := m["name"].(string)
				h, _ := m["sha256"].(string)
				listed[n] = h
			}
		}
	}
	var out []string
	fileChanged := false
	for _, n := range sortedKeys(digests) {
		h, ok := listed[n]
		switch {
		case !ok:
			fileChanged = true
			out = append(out, "added: "+n)
		case h != digests[n]:
			fileChanged = true
			out = append(out, fmt.Sprintf("changed: %s %.12s -> %.12s", n, h, digests[n]))
		}
	}
	for _, n := range sortedKeys(listed) {
		if _, ok := digests[n]; !ok {
			fileChanged = true
			out = append(out, "removed: "+n)
		}
	}
	if o, _ := old["bundleSha256"].(string); o != want {
		out = append(out, fmt.Sprintf("changed: bundleSha256 %.12s -> %.12s", o, want))
	}
	return out, fileChanged
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// fieldFindings applies the per-field caps and the charset allowlist to every
// key and value of every non-receipt file. Everything is printable ASCII,
// except leads quote text, which is upstream text: any rune except control,
// format (bidi), private-use and invalid ones, at most 800 runes.
func fieldFindings(docs map[string]any) []string {
	var out []string
	for _, rel := range sortedKeys(docs) {
		if rel == "receipt.json" {
			continue
		}
		var strs []pathString
		walkStrings(docs[rel], rel, &strs)
		for _, ps := range strs {
			n := utf8.RuneCountInString(ps.val)
			isQuote := quotePathRE.MatchString(ps.path)
			limit := MaxFieldRunes
			if isQuote {
				limit = maxQuoteRunes
			}
			if n > limit {
				out = append(out, fmt.Sprintf("%s: %d characters, more than %d", ps.path, n, limit))
			}
			for _, r := range ps.val {
				if isQuote {
					if r == '\n' || r == '\t' || r == '\r' {
						continue
					}
					if r == utf8.RuneError || unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || unicode.Is(unicode.Co, r) {
						out = append(out, fmt.Sprintf("%s: character U+%04X not allowed", ps.path, r))
						break
					}
				} else if r < 0x20 || r > 0x7e {
					out = append(out, fmt.Sprintf("%s: character U+%04X outside printable ASCII", ps.path, r))
					break
				}
			}
		}
	}
	return out
}
