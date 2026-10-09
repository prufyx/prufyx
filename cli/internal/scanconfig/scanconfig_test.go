// SPDX-License-Identifier: AGPL-3.0-only

package scanconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/intake"
)

const example = `apiVersion: prufyx.io/v1alpha1
kind: ScanConfig
inputs: [rendered/]
current: {kubernetes: 1.27.16}
target:  {kubernetes: 1.30.4}
declarations:
  kubernetes:
    distribution: official_upstream
    resourceScopeComplete: true
    targetApplyRequired: true
`

const head = "apiVersion: prufyx.io/v1alpha1\nkind: ScanConfig\n"

func ptr[T any](v T) *T { return &v }

func TestParseExample(t *testing.T) {
	got, err := Parse([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	want := Config{
		Digest:  Digest([]byte(example)),
		Inputs:  []string{"rendered/"},
		Current: map[string]string{"kubernetes": "1.27.16"},
		Target:  map[string]string{"kubernetes": "1.30.4"},
		Declarations: DeclarationSet{Kubernetes: &KubernetesDeclarations{
			Distribution:          ptr("official_upstream"),
			ResourceScopeComplete: ptr(true),
			TargetApplyRequired:   ptr(true),
		}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	minimal, err := Parse([]byte(head))
	if err != nil || minimal.Inputs != nil || minimal.Current != nil || minimal.Declarations.Kubernetes != nil {
		t.Fatalf("minimal: %+v %v", minimal, err)
	}
}

func TestParseRejectsUnknownKeys(t *testing.T) {
	rows := map[string]string{
		"top level":              head + "extra: 1\n",
		"top level case":         head + "Inputs: [a]\n",
		"under current":          head + "current: {kubernetes: 1.27.16, nope: 1.0.0}\n",
		"current non-kubernetes": head + "current: {not-a-project: 1.0.0}\n",
		"under target":           head + "target: {zzz: 1.0.0}\n",
		"under declarations":     head + "declarations: {argo-cd: {}}\n",
		"declarations other":     head + "declarations: {foo: 1}\n",
		"under kubernetes":       head + "declarations: {kubernetes: {flavor: x}}\n",
		"kubernetes snake case":  head + "declarations: {kubernetes: {resource_scope_complete: true}}\n",
		"apiVersion sibling":     head + "metadata: {name: x}\n",
	}
	for name, text := range rows {
		if _, err := Parse([]byte(text)); !errors.Is(err, ErrConfig) {
			t.Errorf("%s: err=%v", name, err)
		}
	}
}

func TestParseRejectsMalformed(t *testing.T) {
	big := head + "# " + strings.Repeat("x", MaxBytes) + "\n"
	rows := map[string]string{
		"wrong apiVersion":  "apiVersion: prufyx.io/v1\nkind: ScanConfig\n",
		"wrong kind":        "apiVersion: prufyx.io/v1alpha1\nkind: Other\n",
		"missing kind":      "apiVersion: prufyx.io/v1alpha1\n",
		"two documents":     head + "---\n" + head,
		"empty":             "",
		"only comment":      "# nothing\n",
		"not a mapping":     "- a\n- b\n",
		"template braces":   head + "inputs: ['{{ x }}']\n",
		"template dollar":   head + "inputs: ['${X}']\n",
		"template comment":  head + "# ${X}\n",
		"anchor":            head + "inputs: &a [x]\n",
		"alias":             head + "inputs: &a [x]\ncurrent: *a\n",
		"merge key":         head + "<<: {inputs: [x]}\n",
		"duplicate key":     head + "inputs: [a]\ninputs: [b]\n",
		"case-fold dup":     head + "inputs: [a]\nInputs: [b]\n",
		"nested fold dup":   head + "declarations: {kubernetes: {distribution: custom_build, Distribution: custom_build}}\n",
		"non-string key":    head + "1: a\n",
		"custom tag":        head + "inputs: !x [a]\n",
		"oversized":         big,
		"invalid utf8":      head + "# \xff\n",
		"bad distribution":  head + "declarations: {kubernetes: {distribution: Official}}\n",
		"distribution type": head + "declarations: {kubernetes: {distribution: true}}\n",
		"bool as string":    head + "declarations: {kubernetes: {resourceScopeComplete: \"true\"}}\n",
		"bool as number":    head + "declarations: {kubernetes: {targetApplyRequired: 1}}\n",
		"null declaration":  head + "declarations:\n",
		"inputs as string":  head + "inputs: a\n",
		"inputs null entry": head + "inputs: [~]\n",
		"empty inputs":      head + "inputs: []\n",
	}
	for name, text := range rows {
		_, err := Parse([]byte(text))
		if !errors.Is(err, ErrConfig) {
			t.Errorf("%s: err=%v", name, err)
		} else if len(err.Error()) > maxMessage {
			t.Errorf("%s: message too long", name)
		}
	}
}

func TestParseVersionsAndSlugs(t *testing.T) {
	for _, bad := range []string{"1.27", "v1.27.16", "01.2.3", "1.29.3-eks-adc7111", "1.2.3.4", "1.2.x", "", "1..2", "1.2.3+b", " 1.2.3"} {
		for _, section := range []string{"current", "target"} {
			text := head + section + ": {kubernetes: '" + bad + "'}\n"
			if _, err := Parse([]byte(text)); !errors.Is(err, ErrConfig) {
				t.Errorf("%s %q accepted: %v", section, bad, err)
			}
		}
	}
	// A bare number is a YAML float, not a version string.
	if _, err := Parse([]byte(head + "current: {kubernetes: 1.27}\n")); !errors.Is(err, ErrConfig) {
		t.Errorf("float accepted: %v", err)
	}
	for _, good := range []string{"0.0.0", "1.27.16", "10.20.30"} {
		if _, err := Parse([]byte(head + "current: {kubernetes: " + good + "}\n")); err != nil {
			t.Errorf("%q rejected: %v", good, err)
		}
	}
	_, err := Parse([]byte(head + "target: {not-a-real-project: 1.0.0}\n"))
	if err == nil || !strings.Contains(err.Error(), "not-a-real-project") {
		t.Errorf("unknown slug must be named: %v", err)
	}
	_, err = Parse([]byte(head + "target: {" + strings.Repeat("k", 5000) + ": 1.0.0}\n"))
	if err == nil || len(err.Error()) > maxMessage {
		t.Errorf("long key not bounded: %v", err)
	}
}

func TestParseInputsPathSafety(t *testing.T) {
	var many strings.Builder
	for i := 0; i < MaxInputs+1; i++ {
		many.WriteString("  - d" + strings.Repeat("x", i%3) + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "\n")
	}
	bad := map[string]string{
		"absolute":         head + "inputs: [/etc]\n",
		"dotdot":           head + "inputs: ['..']\n",
		"dotdot prefix":    head + "inputs: ['../x']\n",
		"embedded":         head + "inputs: ['a/../b']\n",
		"trailing":         head + "inputs: ['a/..']\n",
		"empty":            head + "inputs: ['']\n",
		"unclean":          head + "inputs: ['a//b']\n",
		"dot slash":        head + "inputs: ['./a']\n",
		"double slash end": head + "inputs: ['a//']\n",
		"slash only":       head + "inputs: ['/']\n",
		"dot end":          head + "inputs: ['a/.']\n",
		"backslash":        head + "inputs: ['a\\b']\n",
		"65 entries":       head + "inputs:\n" + many.String(),
	}
	for name, text := range bad {
		if _, err := Parse([]byte(text)); !errors.Is(err, ErrConfig) {
			t.Errorf("%s accepted: %v", name, err)
		}
	}
	var ok strings.Builder
	for i := 0; i < MaxInputs; i++ {
		ok.WriteString("  - d" + string(rune('a'+i%26)) + string(rune('a'+i/26)) + "\n")
	}
	cfg, err := Parse([]byte(head + "inputs:\n" + ok.String()))
	if err != nil || len(cfg.Inputs) != MaxInputs {
		t.Fatalf("64 entries: %v", err)
	}
	if _, err := Parse([]byte(head + "inputs: [a, b/c, rendered/]\n")); err != nil {
		t.Fatal(err)
	}
}

func TestMergePrecedence(t *testing.T) {
	cfg, err := Parse([]byte(example))
	if err != nil {
		t.Fatal(err)
	}
	// No flags: everything from the file.
	e := Merge(cfg, FlagDeclarations{})
	if e.Distribution != (Value[string]{"official_upstream", true, FromFile}) ||
		e.ResourceScopeComplete != (Value[bool]{true, true, FromFile}) ||
		e.TargetApplyRequired != (Value[bool]{true, true, FromFile}) ||
		e.Current["kubernetes"].Source != FromFile || e.Target["kubernetes"].Value != "1.30.4" ||
		!reflect.DeepEqual(e.Inputs, Value[[]string]{[]string{"rendered/"}, true, FromFile}) {
		t.Fatalf("file only: %+v", e)
	}
	// Flags override file key by key, including false over true.
	e = Merge(cfg, FlagDeclarations{
		Inputs:                []string{"other"},
		Current:               map[string]string{"kubernetes": "1.28.0"},
		Distribution:          ptr("custom_build"),
		ResourceScopeComplete: ptr(false),
	})
	if e.Distribution != (Value[string]{"custom_build", true, FromFlag}) ||
		e.ResourceScopeComplete != (Value[bool]{false, true, FromFlag}) ||
		e.TargetApplyRequired != (Value[bool]{true, true, FromFile}) ||
		e.Current["kubernetes"] != (Value[string]{"1.28.0", true, FromFlag}) ||
		e.Target["kubernetes"].Source != FromFile ||
		e.Inputs.Source != FromFlag || e.Inputs.Value[0] != "other" {
		t.Fatalf("flags: %+v", e)
	}
	// Absent stays absent, and a flag alone is from the flag.
	empty, _ := Parse([]byte(head))
	e = Merge(empty, FlagDeclarations{})
	if e.Distribution.Set || e.ResourceScopeComplete.Set || e.TargetApplyRequired.Set || e.Inputs.Set || e.Current != nil || e.Target != nil {
		t.Fatalf("absent: %+v", e)
	}
	if e.ResourceScopeComplete.Value || e.ResourceScopeComplete.Source != "" {
		t.Fatalf("absent bool defaulted: %+v", e.ResourceScopeComplete)
	}
	e = Merge(empty, FlagDeclarations{TargetApplyRequired: ptr(true), Target: map[string]string{"kubernetes": "1.31.0"}})
	if e.TargetApplyRequired != (Value[bool]{true, true, FromFlag}) || e.Target["kubernetes"].Source != FromFlag || e.ResourceScopeComplete.Set {
		t.Fatalf("flag only: %+v", e)
	}
	// A partial file declaration leaves the other keys absent.
	partial, _ := Parse([]byte(head + "declarations: {kubernetes: {distribution: custom_build}}\n"))
	e = Merge(partial, FlagDeclarations{})
	if !e.Distribution.Set || e.ResourceScopeComplete.Set || e.TargetApplyRequired.Set {
		t.Fatalf("partial: %+v", e)
	}
}

func TestDigest(t *testing.T) {
	raw := []byte(example)
	sum := sha256.Sum256(raw)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if Digest(raw) != want || Digest(raw) != Digest(append([]byte(nil), raw...)) {
		t.Fatal("digest differs")
	}
	cfg, err := Parse(raw)
	if err != nil || cfg.Digest != want {
		t.Fatalf("parse digest %q %v", cfg.Digest, err)
	}
	path := filepath.Join(t.TempDir(), "prufyx.yaml")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path, intake.Strict)
	if err != nil || loaded.Digest != want {
		t.Fatalf("load digest %q %v", loaded.Digest, err)
	}
	if Digest([]byte(example+"\n")) == want {
		t.Fatal("digest ignores bytes")
	}
}

func TestLoadPermissionPolicy(t *testing.T) {
	cases := []struct {
		mode                 os.FileMode
		strict, refuseWrites bool
	}{
		{0o600, true, true},
		{0o400, true, true},
		{0o644, false, true},
		{0o664, false, false},
		{0o660, false, false},
		{0o602, false, false},
		{0o666, false, false},
	}
	for _, tc := range cases {
		dir, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, FileName)
		if err := os.WriteFile(path, []byte(example), tc.mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, tc.mode); err != nil {
			t.Fatal(err)
		}
		for policy, want := range map[intake.PermissionPolicy]bool{intake.Strict: tc.strict, intake.RefuseWritable: tc.refuseWrites} {
			_, err := Load(path, policy)
			if (err == nil) != want {
				t.Errorf("mode %04o policy %d: err=%v want accepted=%v", tc.mode, policy, err, want)
			} else if err != nil && !errors.Is(err, intake.ErrPermissions) {
				t.Errorf("mode %04o policy %d: not a permission error: %v", tc.mode, policy, err)
			}
		}
	}
}

func TestLoadRefusals(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, text string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := write("good.yaml", example)
	if _, err := Load(good, intake.Strict); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load("", intake.Strict); err == nil {
		t.Error("empty path accepted")
	}
	if _, err := Load("-", intake.Strict); err == nil {
		t.Error("stdin accepted")
	}
	if _, err := Load(link, intake.Strict); err == nil {
		t.Error("symlink accepted")
	}
	if _, err := Load(dir, intake.Strict); err == nil {
		t.Error("directory accepted")
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml"), intake.Strict); err == nil {
		t.Error("missing file accepted")
	}
	if _, err := Load(write("big.yaml", head+"# "+strings.Repeat("x", MaxBytes)+"\n"), intake.Strict); err == nil {
		t.Error("oversized file accepted")
	}
	if _, err := Load(write("two.yaml", example+"---\n"+example), intake.Strict); err == nil {
		t.Error("two documents accepted")
	}
	if _, err := Load(write("tmpl.yaml", head+"inputs: ['{{ x }}']\n"), intake.Strict); err == nil {
		t.Error("template accepted")
	}
	if _, err := Load(write("list.yaml", "apiVersion: v1\nkind: List\nitems:\n- apiVersion: prufyx.io/v1alpha1\n  kind: ScanConfig\n"), intake.Strict); err == nil {
		t.Error("List wrapper accepted")
	}
	// Any extension is read when the file is named directly.
	if _, err := Load(write("config.txt", example), intake.Strict); err != nil {
		t.Errorf("named file with other extension: %v", err)
	}
}

func TestDiscover(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	mk := func(parts ...string) string {
		p := filepath.Join(append([]string{root}, parts...)...)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(example), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	// prufyx.yaml only in the root; inputs below it must not find it.
	rootCfg := mk(FileName)
	mk("a", "b", "m.yaml")
	if err := os.MkdirAll(filepath.Join(root, "empty"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, found, err := Discover(root)
	if err != nil || !found || got != rootCfg {
		t.Errorf("directory input: %q %v %v", got, found, err)
	}
	got, found, err = Discover(filepath.Join(root, "x.yaml"))
	if err != nil || found {
		// x.yaml does not exist: nothing is reported, not even the root file.
		t.Errorf("missing input: %q %v %v", got, found, err)
	}
	mk("top.yaml")
	got, found, err = Discover(filepath.Join(root, "top.yaml"))
	if err != nil || !found || got != rootCfg {
		t.Errorf("file input: %q %v %v", got, found, err)
	}
	for _, below := range []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b"), filepath.Join(root, "a", "b", "m.yaml"), filepath.Join(root, "empty")} {
		if got, found, err := Discover(below); err != nil || found {
			t.Errorf("walked up from %s: %q %v %v", below, got, found, err)
		}
	}
	nested := mk("a", "b", FileName)
	if got, found, err := Discover(filepath.Join(root, "a", "b")); err != nil || !found || got != nested {
		t.Errorf("nested directory: %q %v %v", got, found, err)
	}
	if got, found, err := Discover(filepath.Join(root, "a", "b", "m.yaml")); err != nil || !found || got != nested {
		t.Errorf("nested file: %q %v %v", got, found, err)
	}
	if _, found, err := Discover("-"); found || err != nil {
		t.Errorf("stdin: %v %v", found, err)
	}
	if _, _, err := Discover(""); err == nil {
		t.Error("empty input accepted")
	}
	// An unreadable parent directory is an error, not "not found".
	if os.Geteuid() != 0 {
		locked := filepath.Join(root, "locked")
		if err := os.MkdirAll(locked, 0o700); err != nil {
			t.Fatal(err)
		}
		inner := filepath.Join(locked, "d")
		if err := os.MkdirAll(inner, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(locked, 0o700)
		if _, found, err := Discover(inner); err == nil && !found {
			// stat of inner fails with permission denied: must not read as "missing".
			t.Errorf("unreadable path reported as not found")
		}
	}
}

func TestIsConfigDocument(t *testing.T) {
	if !IsConfigDocument("prufyx.io/v1alpha1", "ScanConfig") {
		t.Fatal("exact identity refused")
	}
	for _, c := range [][2]string{{"prufyx.io/v1alpha1", "scanconfig"}, {"prufyx.io/v1alpha1", "ScanConfig "}, {"prufyx.io/v1", "ScanConfig"},
		{"PRUFYX.io/v1alpha1", "ScanConfig"}, {"", ""}, {"v1", "ConfigMap"}, {"prufyx.io/v1alpha1", ""}, {"", "ScanConfig"}} {
		if IsConfigDocument(c[0], c[1]) {
			t.Errorf("%v accepted", c)
		}
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{example, head, "", "---\n---\n", head + "inputs: [a]\n", head + "current: {kubernetes: 1.2.3}\n",
		"{" + strings.Repeat("[", 100), "a: &x [*x]\n", head + strings.Repeat("a: b\n", 50), "\xff\xfe", head + "declarations: {kubernetes: {distribution: custom_build}}\n"} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		cfg, err := Parse(raw)
		if err != nil {
			if !errors.Is(err, ErrConfig) || len(err.Error()) > maxMessage {
				t.Fatalf("unbounded or untyped error (%d bytes)", len(err.Error()))
			}
			return
		}
		if cfg.Digest != Digest(raw) || len(cfg.Inputs) > MaxInputs {
			t.Fatalf("accepted config violates its contract")
		}
		for _, in := range cfg.Inputs {
			if !safeRelative(in) {
				t.Fatalf("unsafe input accepted: %q", in)
			}
		}
	})
}

// A configuration file may name a community project of the reviewed table
// (outside the embedded CNCF landscape catalog): whether the knowledge holds
// data for it is the scan's decision. A name in no catalog is still unknown.
func TestParseNamesCommunityProjects(t *testing.T) {
	config, err := Parse([]byte(head + "current: {gateway-api: 1.1.0}\ntarget: {gateway-api: 1.2.0}\n"))
	if err != nil {
		t.Fatalf("community project rejected: %v", err)
	}
	if config.Current["gateway-api"] != "1.1.0" || config.Target["gateway-api"] != "1.2.0" {
		t.Fatalf("config %+v", config)
	}
	for _, text := range []string{"target: {gateway-apis: 1.2.0}\n", "target: {Gateway-API: 1.2.0}\n"} {
		if _, err := Parse([]byte(head + text)); !errors.Is(err, ErrConfig) {
			t.Errorf("%q accepted: %v", text, err)
		}
	}
}
