// SPDX-License-Identifier: AGPL-3.0-only

package knowledgeauto

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

func TestDefaultRoot(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", "/data")
	if root, ok := DefaultRoot(); !ok || root != "/data/prufyx/knowledge/cncf-projects" {
		t.Fatalf("xdg: %q %v", root, ok)
	}
	t.Setenv("XDG_DATA_HOME", "relative")
	t.Setenv("HOME", "/home/u")
	if root, ok := DefaultRoot(); !ok || root != "/home/u/.local/share/prufyx/knowledge/cncf-projects" {
		t.Fatalf("home: %q %v", root, ok)
	}
}

func TestLocate(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_DATA_HOME", base)
	if _, present, err := Locate(); present || err != nil {
		t.Fatalf("absent: %v %v", present, err)
	}
	root, err := EnsureRoot()
	if err != nil {
		t.Fatal(err)
	}
	if _, present, err := Locate(); present || err != nil {
		t.Fatalf("empty dir is no store: %v %v", present, err)
	}
	if err := os.WriteFile(filepath.Join(root, "stray"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, present, err := Locate(); !present || !errors.Is(err, ErrRefused) {
		t.Fatalf("not a store: %v %v", present, err)
	}
	if err := os.WriteFile(filepath.Join(root, "profile.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, present, err := Locate(); !present || err != nil {
		t.Fatalf("store: %v %v", present, err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, present, err := Locate(); !present || !errors.Is(err, ErrRefused) {
		t.Fatalf("mode: %v %v", present, err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, root); err != nil {
		t.Fatal(err)
	}
	if _, present, err := Locate(); !present || !errors.Is(err, ErrRefused) {
		t.Fatalf("symlink: %v %v", present, err)
	}
}

func TestCheckPinAndReason(t *testing.T) {
	good := "sha256:" + "ab01234567890123456789012345678901234567890123456789012345678901"
	if CheckPin("", "anything") != nil || CheckPin(good, good) != nil || CheckPin(good, good[7:]) != nil {
		t.Fatal("accepted cases refused")
	}
	if !errors.Is(CheckPin(good, "sha256:"+"cd01234567890123456789012345678901234567890123456789012345678901"), ErrRefused) || !errors.Is(CheckPin(good, ""), ErrRefused) {
		t.Fatal("wrong root accepted")
	}
	if Reason(knowledge.ErrExpired) == Reason(knowledge.ErrRollback) || Reason(errors.New("x")) == "" {
		t.Fatal("reason classes")
	}
}

func TestEnsureRootAcceptsSymlinkedBase(t *testing.T) {
	// A symlinked base (XDG_DATA_HOME or ~/.local/share) with no prufyx yet.
	real := t.TempDir()
	link := filepath.Join(t.TempDir(), "share")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_DATA_HOME", link)
	root, err := EnsureRoot()
	if err != nil {
		t.Fatalf("symlinked base refused: %v", err)
	}
	info, err := os.Lstat(filepath.Join(real, "prufyx", "knowledge", "cncf-projects"))
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("not created privately below the link target: %v %v", info, err)
	}
	if _, present, err := Locate(); err != nil || present {
		t.Fatalf("Locate under a symlinked base: root=%s present=%v err=%v", root, present, err)
	}
}

func TestLocateNeverCommittedStoreIsAbsent(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	root, err := EnsureRoot()
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(root, name), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// What a failed first import leaves.
	write(".lock")
	write("profile.json")
	write("clock-floor.json")
	if err := os.Mkdir(filepath.Join(root, "trust"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, present, err := Locate(); err != nil || present {
		t.Fatalf("bootstrap leftovers: present=%v err=%v", present, err)
	}
	// A committed selection, a pending import, or anything else is refused or present.
	for _, name := range []string{"selection.json", "import-pending.json"} {
		write(name)
		if _, present, err := Locate(); err != nil || !present {
			t.Fatalf("%s: present=%v err=%v", name, present, err)
		}
		os.Remove(filepath.Join(root, name))
	}
	if err := os.Mkdir(filepath.Join(root, "admissions"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, present, _ := Locate(); !present {
		t.Fatal("a store with admissions counted as absent")
	}
	os.Remove(filepath.Join(root, "admissions"))
	// A symbolic link in place of an artefact is not a leftover.
	os.Remove(filepath.Join(root, "clock-floor.json"))
	if err := os.Symlink("/etc/hosts", filepath.Join(root, "clock-floor.json")); err != nil {
		t.Fatal(err)
	}
	if _, present, _ := Locate(); !present {
		t.Fatal("a symbolic link counted as absent")
	}
}

func TestStalenessNote(t *testing.T) {
	note := StalenessNote("2026-01-02T03:04:05Z", "2026-04-02T00:00:00Z")
	for _, want := range []string{"2026-01-02T03:04:05Z", "expires 2026-04-02T00:00:00Z", "newer than the embedded"} {
		if !strings.Contains(note, want) {
			t.Fatalf("%q lacks %q", note, want)
		}
	}
}

func TestChoose(t *testing.T) {
	d := func(v string) time.Time {
		at, err := time.Parse(time.RFC3339, v)
		if err != nil {
			t.Fatal(err)
		}
		return at
	}
	for _, c := range []struct {
		store, embedded string
		identical       bool
		stale           string
		chosen, reason  string
	}{
		{"2026-11-05T00:00:00Z", "2026-10-29T00:00:00Z", false, "", SourceLocalDB, ReasonStoreNewer},
		{"2026-10-17T00:00:00Z", "2026-10-29T00:00:00Z", false, "", SourceEmbedded, ReasonStoreOlder},
		{"2026-10-29T00:00:00Z", "2026-10-29T00:00:00Z", true, "", SourceEmbedded, ReasonIdentical},
		{"2026-10-29T00:00:00Z", "2026-10-29T00:00:00Z", false, "", SourceLocalDB, ReasonStoreCorrected},
		// Newer overall but older for one project: embedded.
		{"2026-10-17T00:00:00Z", "2026-10-29T00:00:00Z", false, "argo-cd", SourceEmbedded, ReasonStoreOlder},
	} {
		got := Choose(d(c.store), d(c.embedded), c.identical, c.stale)
		if got.Chosen != c.chosen || got.Reason != c.reason {
			t.Fatalf("%+v: %+v", c, got)
		}
	}
}

func TestFallbackWhy(t *testing.T) {
	if got := FallbackWhy(ReasonStoreExpired); got != ExpiredWhy {
		t.Fatalf("expired: %q", got)
	}
	if got := FallbackWhy("other"); got == ExpiredWhy || got == "" {
		t.Fatalf("unknown reason got the expiry text: %q", got)
	}
	why := Choose(time.Unix(1, 0), time.Unix(2, 0), false, "argo-cd").EmbeddedWhy()
	if !strings.Contains(why, "argo-cd") {
		t.Fatalf("stale project not named: %q", why)
	}
}

func TestFallbackReason(t *testing.T) {
	for _, c := range []struct {
		err    error
		reason string
	}{
		{fmt.Errorf("x: %w", knowledge.ErrExpired), ReasonStoreExpired},
		{fmt.Errorf("x: %w", knowledge.ErrUnsupportedKnowledge), ReasonStoreTooNew},
		{&knowledge.UnsupportedError{Reason: "r", MinVersion: "v1.0.0"}, ReasonStoreTooNew},
		{fmt.Errorf("x: %w", knowledge.ErrTrustAdvanced), ReasonStoreTrustAdvanced},
	} {
		if r, ok := FallbackReason(c.err); !ok || r != c.reason {
			t.Fatalf("%v: %q %v", c.err, r, ok)
		}
	}
	hard := []error{knowledge.ErrIntegrity, knowledge.ErrRollback, knowledge.ErrFeedBehind, knowledge.ErrPinnedRootMismatch,
		knowledge.ErrNoSelection, knowledge.ErrLayout, knowledge.ErrRecoveryRequired}
	cases := []error{nil, errors.New("other")}
	cases = append(cases, hard...)
	for _, h := range hard {
		for _, soft := range []error{knowledge.ErrExpired, knowledge.ErrUnsupportedKnowledge, knowledge.ErrTrustAdvanced} {
			cases = append(cases, errors.Join(soft, h), errors.Join(h, soft))
		}
	}
	for _, err := range cases {
		if r, ok := FallbackReason(err); ok || r != "" {
			t.Fatalf("%v: %q %v", err, r, ok)
		}
	}
}

func TestFallbackWarning(t *testing.T) {
	if got := FallbackWarning(ReasonStoreTooNew, "v0.3.0", ""); !strings.Contains(got, "a newer prufyx is needed for this knowledge (min version v0.3.0)") {
		t.Fatalf("too new: %q", got)
	}
	if got := FallbackWarning(ReasonStoreTooNew, "", ""); !strings.HasSuffix(got, "a newer prufyx is needed for this knowledge") {
		t.Fatalf("too new, no version: %q", got)
	}
	if got := FallbackWarning(ReasonStoreTrustAdvanced, "", "/s"); !strings.Contains(got, "upgrade prufyx, or remove /s and run `prufyx db update`") {
		t.Fatalf("trust advanced: %q", got)
	}
}

// The reason enum of the scan report schema lists every fallback reason.
func TestFallbackReasonsAreInTheScanSchema(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "generated", "schemas", "scan-report-v1alpha1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	var enum []string
	// The knowledgeSelection object is the one whose "chosen" member exists.
	var walk func(v any)
	walk = func(v any) {
		switch n := v.(type) {
		case map[string]any:
			if props, ok := n["properties"].(map[string]any); ok {
				if _, chosen := props["chosen"]; chosen {
					if reason, ok := props["reason"].(map[string]any); ok {
						for _, e := range reason["enum"].([]any) {
							enum = append(enum, e.(string))
						}
					}
				}
			}
			for _, c := range n {
				walk(c)
			}
		case []any:
			for _, c := range n {
				walk(c)
			}
		}
	}
	walk(doc)
	if len(enum) == 0 {
		t.Fatal("no knowledgeSelection reason enum in the schema")
	}
	for _, reason := range []string{ReasonStoreNewer, ReasonStoreCorrected, ReasonStoreOlder, ReasonIdentical, ReasonNoStore, ReasonForced, ReasonStoreExpired, ReasonStoreTooNew, ReasonStoreTrustAdvanced} {
		found := false
		for _, e := range enum {
			found = found || e == reason
		}
		if !found {
			t.Fatalf("%s missing from the reason enum %v", reason, enum)
		}
	}
}
