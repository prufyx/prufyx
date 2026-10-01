// SPDX-License-Identifier: AGPL-3.0-only

// Package releasegate derives and verifies the deterministic Community source
// manifest. It is a local maintainer tool: it does not publish, attest, or
// mutate a checkout.
package releasegate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	SchemaV1           = "prufyx.io/community-shipping-policy/v1"
	SchemaV2           = "prufyx.io/community-shipping-policy/v2"
	ManifestSchema     = "prufyx.io/community-source-manifest/v1"
	MaxFileBytes       = 32 << 20
	MaxTotalBytes      = 256 << 20
	MaxDiagnosticBytes = 16 << 10
	maxGoCommandTime   = 10 * time.Minute
)

var ErrRejected = errors.New("community release input rejected")
var privateKey = regexp.MustCompile(`-----BEGIN (?:[A-Z0-9][A-Z0-9 -]{0,64} )?PRIVATE KEY(?: BLOCK)?-----`)
var safeName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
var goVersion = regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`)
var digest64 = regexp.MustCompile(`^[0-9a-f]{64}$`)
var h1Digest = regexp.MustCompile(`^h1:[A-Za-z0-9+/]{43}=$`)

type GateError struct{ Message string }

func (e *GateError) Error() string { return e.Message }
func reject(format string, args ...any) error {
	return &GateError{Message: fmt.Sprintf(format, args...)}
}

// Options controls one local gate operation. Go is the exact executable to
// use; an empty value means "go". Output files are created exclusively.
type Options struct {
	SourceRoot, PolicyPath, ManifestPath, OutputPath, Go string
	RunNativeChecks                                      bool
}

type Manifest struct {
	SchemaVersion      string                  `json:"schemaVersion"`
	BinaryName         string                  `json:"binaryName"`
	BuildTargets       []string                `json:"buildTargets"`
	SourceBuildTargets []string                `json:"sourceBuildTargets"`
	Entrypoints        []string                `json:"entrypoints"`
	ModuleRoot         string                  `json:"moduleRoot,omitempty"`
	TestTags           []string                `json:"testTags"`
	Files              []FileEntry             `json:"files"`
	Packages           []PackageReceipt        `json:"packages"`
	PolicyDigest       string                  `json:"policyDigest"`
	RequiredGoVersion  string                  `json:"requiredGoVersion"`
	ToolchainArchives  map[string]string       `json:"toolchainArchives"`
	ModuleMode         string                  `json:"moduleMode,omitempty"`
	VendorTreeDigest   string                  `json:"vendorTreeDigest,omitempty"`
	ExternalModules    []ExternalModuleReceipt `json:"externalModules,omitempty"`
	BinaryResources    []BinaryResource        `json:"binaryResources,omitempty"`
	ManifestDigest     string                  `json:"manifestDigest,omitempty"`
}
type FileEntry struct {
	Mode   string `json:"mode"`
	Path   string `json:"path"`
	Role   string `json:"role"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}
type PackageReceipt struct {
	ImportPath  string   `json:"importPath"`
	Name        string   `json:"name"`
	Path        string   `json:"path"`
	DirectTests []string `json:"directTests"`
}
type ExternalModuleReceipt struct {
	Path            string `json:"path"`
	Version         string `json:"version"`
	ModuleSum       string `json:"moduleSum"`
	GoModSum        string `json:"goModSum"`
	LicenseDeclared string `json:"licenseDeclared"`
}
type BinaryResource struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

func canonical(v any) ([]byte, error) {
	// Normalize typed receipts through a UseNumber decode before marshaling. Go
	// marshals map keys in lexical order but preserves struct declaration order;
	// Verify decodes a map, so both paths must share this sorted-key form.
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var normalized any
	if err := dec.Decode(&normalized); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(normalized); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
func digest(b []byte) string      { h := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(h[:]) }
func sha256Bytes(b []byte) []byte { h := sha256.Sum256(b); return h[:] }

// decodeStrict rejects duplicate keys, trailing values, and malformed JSON.
func decodeStrict(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeValue(dec, 0)
	if err != nil {
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, errors.New("trailing JSON value")
		}
		return nil, err
	}
	return v, nil
}
func decodeValue(dec *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, errors.New("JSON nesting limit exceeded")
	}
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := t.(json.Delim); ok {
		switch d {
		case '{':
			m := map[string]any{}
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key, ok := k.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if _, ok := m[key]; ok {
					return nil, fmt.Errorf("duplicate JSON key: %s", key)
				}
				val, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				m[key] = val
			}
			_, err = dec.Token()
			return m, err
		case '[':
			a := []any{}
			for dec.More() {
				val, err := decodeValue(dec, depth+1)
				if err != nil {
					return nil, err
				}
				a = append(a, val)
			}
			_, err = dec.Token()
			return a, err
		}
	}
	switch x := t.(type) {
	case string, json.Number, bool, nil:
		return x, nil
	}
	return nil, errors.New("invalid JSON value")
}
func object(v any) (map[string]any, error) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, errors.New("JSON value must be an object")
	}
	return m, nil
}
func exactKeys(m map[string]any, keys ...string) bool {
	wanted := map[string]bool{}
	for _, k := range keys {
		wanted[k] = true
	}
	if len(m) != len(wanted) {
		return false
	}
	for k := range m {
		if !wanted[k] {
			return false
		}
	}
	return true
}
func listStrings(v any) ([]string, bool) {
	a, ok := v.([]any)
	if !ok {
		return nil, false
	}
	out := make([]string, len(a))
	for i, x := range a {
		out[i], ok = x.(string)
		if !ok {
			return nil, false
		}
	}
	return out, true
}
func equalStrings(v any, want []string) bool {
	if got, ok := v.([]string); ok {
		if len(got) != len(want) {
			return false
		}
		for i := range got {
			if got[i] != want[i] {
				return false
			}
		}
		return true
	}
	got, ok := listStrings(v)
	if !ok || len(got) != len(want) {
		return false
	}
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}
func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}
func safeRelative(raw, label string) (string, error) {
	if raw == "" || strings.Contains(raw, "\\") || !isASCII(raw) || filepath.IsAbs(raw) {
		return "", reject("invalid %s", label)
	}
	for _, p := range strings.Split(raw, "/") {
		if p == "" || p == "." || p == ".." {
			return "", reject("invalid %s", label)
		}
	}
	clean := filepath.ToSlash(filepath.Clean(raw))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", reject("invalid %s", label)
	}
	for _, p := range strings.Split(clean, "/") {
		if p == "" || p == "." || p == ".." {
			return "", reject("invalid %s", label)
		}
	}
	return clean, nil
}

func validatePolicy(v map[string]any) (map[string]any, error) {
	schema, ok := v["schemaVersion"].(string)
	if !ok || (schema != SchemaV1 && schema != SchemaV2) {
		return nil, reject("shipping policy has an unknown schema")
	}
	base := []string{"schemaVersion", "moduleRoot", "entrypoints", "binaryName", "buildTargets", "requiredGoVersion", "allowExternalModules", "requiredPaths", "sourceBuildTargets", "testPolicy", "toolchainArchives"}
	if schema == SchemaV2 {
		base = append(base, "vendorRoot", "vendorTreeDigest", "externalModules", "binaryResources")
	}
	if !exactKeys(v, base...) {
		return nil, reject("shipping policy has an unknown or missing field")
	}
	mr, ok := v["moduleRoot"].(string)
	if !ok {
		return nil, reject("moduleRoot is invalid")
	}
	mr, err := safeRelative(mr, "moduleRoot")
	if err != nil {
		return nil, err
	}
	v["moduleRoot"] = mr
	bn, ok := v["binaryName"].(string)
	if !ok || !safeName.MatchString(bn) {
		return nil, reject("invalid binaryName")
	}
	gv, ok := v["requiredGoVersion"].(string)
	if !ok || !goVersion.MatchString(gv) {
		return nil, reject("requiredGoVersion must pin a patch release")
	}
	allow, ok := v["allowExternalModules"].(bool)
	if !ok || allow != (schema == SchemaV2) {
		return nil, reject("allowExternalModules does not match policy schema")
	}
	es, ok := listStrings(v["entrypoints"])
	if !ok || len(es) == 0 {
		return nil, reject("entrypoints must be non-empty")
	}
	for _, e := range es {
		if !strings.HasPrefix(e, "./") || !safeName.MatchString(filepath.Base(e)) {
			return nil, reject("invalid entrypoint: %s", e)
		}
	}
	if !equalStrings(v["buildTargets"], []string{"linux/amd64", "linux/arm64"}) || !equalStrings(v["sourceBuildTargets"], []string{"linux/amd64", "linux/arm64", "darwin/arm64"}) {
		return nil, reject("build target tuples are not the fixed Community set")
	}
	archives, ok := v["toolchainArchives"].(map[string]any)
	if !ok || len(archives) != 3 {
		return nil, reject("toolchainArchives must cover every source-build tuple")
	}
	for _, t := range []string{"linux/amd64", "linux/arm64", "darwin/arm64"} {
		d, ok := archives[t].(string)
		if !ok || !digest64.MatchString(d) {
			return nil, reject("invalid toolchain archive digest")
		}
	}
	paths, ok := v["requiredPaths"].([]any)
	if !ok || len(paths) == 0 {
		return nil, reject("requiredPaths must be non-empty")
	}
	seen := map[string]bool{}
	for _, x := range paths {
		m, ok := x.(map[string]any)
		if !ok || len(m) < 2 || len(m) > 3 {
			return nil, reject("requiredPaths entries have a closed schema")
		}
		p, ok := m["path"].(string)
		if !ok {
			return nil, reject("required path is invalid")
		}
		p, err = safeRelative(p, "required path")
		if err != nil {
			return nil, err
		}
		if seen[p] {
			return nil, reject("duplicate required path: %s", p)
		}
		seen[p] = true
		role, ok := m["role"].(string)
		if !ok || !regexp.MustCompile(`^[a-z][a-z0-9-]*$`).MatchString(role) {
			return nil, reject("invalid role for %s", p)
		}
		if r, exists := m["recursive"]; exists {
			b, ok := r.(bool)
			if !ok || !b {
				return nil, reject("recursive must be true when present: %s", p)
			}
		}
	}
	tp, ok := v["testPolicy"].(map[string]any)
	if !ok || len(tp) != 2 {
		return nil, reject("Community policy requires direct tests and parityreview")
	}
	req, ok := tp["requireDirectTestsForProductionPackages"].(bool)
	tags, ok2 := listStrings(tp["testTags"])
	if !ok || !ok2 || !req || !equalStrings(tags, []string{"parityreview"}) {
		return nil, reject("Community policy requires direct tests and parityreview")
	}
	if schema == SchemaV2 {
		if err := validateV2(v, mr); err != nil {
			return nil, err
		}
	}
	return v, nil
}
func validateV2(v map[string]any, mr string) error {
	vr, ok := v["vendorRoot"].(string)
	if !ok {
		return reject("vendorRoot is invalid")
	}
	vr, err := safeRelative(vr, "vendorRoot")
	if err != nil {
		return err
	}
	if vr != mr+"/vendor" {
		return reject("vendorRoot must be the module vendor directory")
	}
	v["vendorRoot"] = vr
	d, ok := v["vendorTreeDigest"].(string)
	if !ok || !strings.HasPrefix(d, "sha256:") || !digest64.MatchString(strings.TrimPrefix(d, "sha256:")) {
		return reject("vendorTreeDigest is invalid")
	}
	mods, ok := v["externalModules"].([]any)
	if !ok || len(mods) == 0 {
		return reject("externalModules must be non-empty")
	}
	last := ""
	noticeDest := map[string]bool{}
	for _, x := range mods {
		m, ok := x.(map[string]any)
		if !ok || !exactKeys(m, "path", "version", "moduleSum", "goModSum", "licenseDeclared", "notices") {
			return reject("external module entries have a closed schema")
		}
		p, a := m["path"].(string)
		ver, b := m["version"].(string)
		ms, c := m["moduleSum"].(string)
		gs, e := m["goModSum"].(string)
		lic, f := m["licenseDeclared"].(string)
		if !a || !b || !c || !e || !f || p == "" || ver == "" || !h1Digest.MatchString(ms) || !h1Digest.MatchString(gs) || !safeName.MatchString(lic) {
			return reject("invalid external module profile")
		}
		if last != "" && p <= last {
			return reject("external modules must be unique and sorted")
		}
		last = p
		ns, ok := m["notices"].([]any)
		if !ok || len(ns) == 0 {
			return reject("external module has no distribution notice: %s", p)
		}
		for _, y := range ns {
			nm, ok := y.(map[string]any)
			if !ok || !exactKeys(nm, "sourcePath", "distributionPath", "sha256") {
				return reject("external module notice has a closed schema")
			}
			sp, a := nm["sourcePath"].(string)
			dp, b := nm["distributionPath"].(string)
			hd, c := nm["sha256"].(string)
			if !a || !b || !c {
				return reject("invalid external module notice")
			}
			sp, err = safeRelative(sp, "vendor notice source")
			if err != nil {
				return err
			}
			dp, err = safeRelative(dp, "distribution notice")
			if err != nil {
				return err
			}
			if !strings.HasPrefix(sp, vr+"/") || !strings.HasPrefix(dp, "LICENSES/") || !digest64.MatchString(hd) || noticeDest[dp] {
				return reject("invalid or duplicate distribution notice")
			}
			noticeDest[dp] = true
			nm["sourcePath"] = sp
			nm["distributionPath"] = dp
		}
	}
	res, ok := v["binaryResources"].([]any)
	if !ok || len(res) == 0 {
		return reject("binaryResources must be non-empty")
	}
	last = ""
	for _, x := range res {
		m, ok := x.(map[string]any)
		if !ok || !exactKeys(m, "path", "sha256") {
			return reject("binary resource has a closed schema")
		}
		p, a := m["path"].(string)
		d, b := m["sha256"].(string)
		if !a || !b || !strings.HasPrefix(p, vr+"/") || !digest64.MatchString(d) || p <= last {
			return reject("binary resources must be unique and sorted")
		}
		last = p
	}
	return nil
}

func validateModuleSums(root string, policy map[string]any) error {
	moduleRoot := policy["moduleRoot"].(string)
	raw, err := externalRead(filepath.Join(root, filepath.FromSlash(moduleRoot), "go.sum"), "go.sum")
	if err != nil {
		return err
	}
	return validateModuleSumsBytes(raw, policy)
}

// validateModuleSumsBytes validates the exact captured go.sum bytes. Keeping
// this separate from the source read lets derive bind the staged closure, not
// only a pre-collection filesystem observation.
func validateModuleSumsBytes(raw []byte, policy map[string]any) error {
	seen := map[string]bool{}
	found := map[string]string{}
	for _, line := range strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n") {
		f := strings.Split(line, " ")
		if len(f) != 3 || f[0] == "" || f[1] == "" || f[2] == "" || seen[f[0]+"\x00"+f[1]] {
			return reject("go.sum contains a non-canonical or duplicate module identity")
		}
		key := f[0] + "\x00" + f[1]
		seen[key] = true
		found[key] = f[2]
	}
	for _, x := range policy["externalModules"].([]any) {
		m := x.(map[string]any)
		path, ver := m["path"].(string), m["version"].(string)
		if found[path+"\x00"+ver] != m["moduleSum"] || found[path+"\x00"+ver+"/go.mod"] != m["goModSum"] {
			return reject("external module checksums differ from policy: %s", path)
		}
	}
	return nil
}

func validateVendorModulesBytes(raw []byte, policy map[string]any) error {
	want := []string{}
	for _, x := range policy["externalModules"].([]any) {
		m := x.(map[string]any)
		want = append(want, m["path"].(string)+" "+m["version"].(string))
	}
	got := []string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if strings.HasPrefix(line, "# ") {
			f := strings.Fields(line)
			if len(f) != 3 {
				return reject("vendor/modules.txt contains a replacement or malformed module header")
			}
			got = append(got, f[1]+" "+f[2])
		}
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		return reject("vendored Go module closure differs from policy")
	}
	return nil
}

func validateVendorTree(root string, policy map[string]any) error {
	vr := policy["vendorRoot"].(string)
	base := filepath.Join(root, filepath.FromSlash(vr))
	st, err := os.Lstat(base)
	if err != nil || !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return reject("vendor root is missing or unsafe")
	}
	resources := map[string]string{}
	for _, x := range policy["binaryResources"].([]any) {
		m := x.(map[string]any)
		resources[m["path"].(string)] = m["sha256"].(string)
	}
	entries := []map[string]any{}
	seen := map[string]bool{}
	err = filepath.Walk(base, func(name string, info os.FileInfo, e error) error {
		if e != nil {
			return e
		}
		if name == base || info.IsDir() {
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return reject("vendor tree contains a non-regular entry: %s", name)
		}
		rel, _ := filepath.Rel(root, name)
		rel = filepath.ToSlash(rel)
		b, mode, e := stableRead(root, rel, true)
		if e != nil {
			return e
		}
		h := sha256.Sum256(b)
		hd := hex.EncodeToString(h[:])
		if bytes.IndexByte(b, 0) >= 0 && resources[rel] == "" {
			return reject("unreviewed binary content in vendor tree: %s", rel)
		}
		if expected := resources[rel]; expected != "" && expected != hd {
			return reject("binary vendor resource differs from policy: %s", rel)
		}
		seen[rel] = true
		entries = append(entries, map[string]any{"mode": fmt.Sprintf("%04o", mode.Perm()), "path": rel, "sha256": hd, "size": len(b)})
		return nil
	})
	if err != nil {
		return err
	}
	for p := range resources {
		if !seen[p] {
			return reject("binary vendor resource is absent from exact vendor tree")
		}
	}
	for _, x := range policy["externalModules"].([]any) {
		m := x.(map[string]any)
		for _, y := range m["notices"].([]any) {
			n := y.(map[string]any)
			src, _, e := stableRead(root, n["sourcePath"].(string), true)
			if e != nil {
				return e
			}
			dst, _, e := stableRead(root, n["distributionPath"].(string), false)
			if e != nil {
				return e
			}
			h := sha256.Sum256(src)
			if !bytes.Equal(src, dst) || hex.EncodeToString(h[:]) != n["sha256"] {
				return reject("external module notice binding differs: %s", m["path"])
			}
		}
	}
	// Preserve the original policy's PurePosixPath(parts) ordering. Plain string
	// ordering differs when a path component is a prefix of another component
	// followed by punctuation, and would change the vendor-tree binding.
	sort.Slice(entries, func(i, j int) bool { return vendorPathLess(entries[i]["path"].(string), entries[j]["path"].(string)) })
	raw, _ := canonical(entries)
	if got := digest(raw); got != policy["vendorTreeDigest"] {
		return reject("vendor tree differs from exact Community policy")
	}
	return nil
}

func vendorPathLess(left, right string) bool {
	a, b := strings.Split(left, "/"), strings.Split(right, "/")
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return len(a) < len(b)
}

// capturedVendorTreeDigest rebuilds the legacy four-field vendor receipt from
// selected bytes. FileEntry roles are intentionally excluded: the policy
// binds content, mode, path, and size only.
func capturedVendorTreeDigest(entries []FileEntry, blobs map[string][]byte, vendorRoot string) (string, error) {
	captured := []map[string]any{}
	prefix := vendorRoot + "/"
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Path, prefix) {
			continue
		}
		blob, ok := blobs[entry.Path]
		if !ok {
			return "", reject("captured vendor file is absent")
		}
		h := sha256.Sum256(blob)
		if hex.EncodeToString(h[:]) != entry.SHA256 || int64(len(blob)) != entry.Size {
			return "", reject("captured vendor file differs from manifest")
		}
		captured = append(captured, map[string]any{
			"mode": entry.Mode, "path": entry.Path, "sha256": entry.SHA256, "size": entry.Size,
		})
	}
	sort.Slice(captured, func(i, j int) bool { return vendorPathLess(captured[i]["path"].(string), captured[j]["path"].(string)) })
	raw, err := canonical(captured)
	if err != nil {
		return "", err
	}
	return digest(raw), nil
}

func validateCapturedV2Bindings(entries []FileEntry, blobs map[string][]byte, policy map[string]any, policyPath string, policyRaw []byte) error {
	capturedPolicy, ok := blobs[policyPath]
	if !ok || !bytes.Equal(capturedPolicy, policyRaw) {
		return reject("captured shipping policy differs from validated policy bytes")
	}
	vendorRoot := policy["vendorRoot"].(string)
	vendorDigest, err := capturedVendorTreeDigest(entries, blobs, vendorRoot)
	if err != nil {
		return err
	}
	if vendorDigest != policy["vendorTreeDigest"] {
		return reject("captured vendor tree differs from exact Community policy")
	}
	moduleRoot := policy["moduleRoot"].(string)
	vendorModules, ok := blobs[vendorRoot+"/modules.txt"]
	if !ok {
		return reject("captured vendor/modules.txt is absent")
	}
	if err := validateVendorModulesBytes(vendorModules, policy); err != nil {
		return err
	}
	moduleSums, ok := blobs[moduleRoot+"/go.sum"]
	if !ok {
		return reject("captured go.sum is absent")
	}
	return validateModuleSumsBytes(moduleSums, policy)
}

func command(goBin string, args []string, dir string, env []string) ([]byte, error) {
	if goBin == "" {
		goBin = "go"
	}
	ctx, cancel := context.WithTimeout(context.Background(), maxGoCommandTime)
	defer cancel()
	c := exec.CommandContext(ctx, goBin, args...)
	c.Dir = dir
	c.Env = env
	var out, diagnostic boundedBuffer
	out.limit = MaxTotalBytes
	diagnostic.limit = MaxDiagnosticBytes
	c.Stdout = &out
	c.Stderr = &diagnostic
	err := c.Run()
	if err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, reject("Go command exceeded maintainer execution limit")
		}
		if _, ok := err.(*exec.ExitError); ok {
			return nil, reject("Go command failed: %s", tail(diagnostic.Bytes()))
		}
		return nil, reject("cannot execute Go toolchain: %v", err)
	}
	if out.exceeded {
		return nil, reject("Go command output exceeds its bound")
	}
	return out.Bytes(), nil
}

type boundedBuffer struct {
	bytes.Buffer
	limit    int64
	exceeded bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if int64(b.Len()+len(p)) > b.limit {
		b.exceeded = true
		return 0, io.ErrShortWrite
	}
	return b.Buffer.Write(p)
}
func tail(b []byte) string {
	if len(b) > MaxDiagnosticBytes {
		b = b[len(b)-MaxDiagnosticBytes:]
	}
	return strings.TrimSpace(string(b))
}
func baseEnv(vendor bool, extra ...string) []string {
	env := []string{}
	for _, k := range []string{"PATH", "HOME", "TMPDIR", "GOROOT", "GOPATH", "GOCACHE"} {
		if v := os.Getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	flags := "-buildvcs=false"
	if vendor {
		flags = "-mod=vendor " + flags
	}
	env = append(env, "CGO_ENABLED=0", "GOFLAGS="+flags, "GOEXPERIMENT=", "GOAMD64=v1", "GOARM64=v8.0", "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local", "GOWORK=off")
	return append(env, extra...)
}
func withoutEnv(env []string, key string) []string {
	out := env[:0]
	for _, e := range env {
		if !strings.HasPrefix(e, key+"=") {
			out = append(out, e)
		}
	}
	return out
}

type goPackage struct {
	ImportPath                                                                                                                                                                      string
	Dir                                                                                                                                                                             string
	Name                                                                                                                                                                            string
	Module                                                                                                                                                                          map[string]any
	ForTest                                                                                                                                                                         string
	GoFiles, CgoFiles, CFiles, CXXFiles, MFiles, HFiles, FFiles, SFiles, SwigFiles, SwigCXXFiles, SysoFiles, TestGoFiles, XTestGoFiles, EmbedFiles, TestEmbedFiles, XTestEmbedFiles []string
}

func decodeStream(raw []byte) ([]goPackage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	out := []goPackage{}
	for {
		var p goPackage
		err := dec.Decode(&p)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}
func inModule(p goPackage, module string) bool { return p.Module != nil && p.Module["Path"] == module }
func addFile(files map[string]string, p, role string) {
	priority := map[string]int{"production-go": 100, "production-embed": 95, "test-go": 90, "test-support-go": 85, "test-support-embed": 84, "testdata": 80, "module": 75}
	if old, ok := files[p]; !ok || priority[role] > priority[old] {
		files[p] = role
	}
}
func stableRead(root, rel string, binary bool) ([]byte, os.FileMode, error) {
	if _, err := safeRelative(rel, "manifest path"); err != nil {
		return nil, 0, err
	}
	parts := strings.Split(rel, "/")
	full := filepath.Join(root, filepath.FromSlash(rel))
	rootFD, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, reject("cannot safely open source root")
	}
	parent := rootFD
	defer func() { _ = unix.Close(rootFD) }()
	for _, part := range parts[:len(parts)-1] {
		next, e := unix.Openat(parent, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if e != nil {
			if parent != rootFD {
				_ = unix.Close(parent)
			}
			return nil, 0, reject("cannot safely open selected source %s", rel)
		}
		if parent != rootFD {
			_ = unix.Close(parent)
		}
		parent = next
	}
	fd, err := unix.Openat(parent, parts[len(parts)-1], unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if parent != rootFD {
		_ = unix.Close(parent)
	}
	if err != nil {
		return nil, 0, reject("cannot safely read selected source %s", rel)
	}
	f := os.NewFile(uintptr(fd), full)
	if f == nil {
		syscall.Close(fd)
		return nil, 0, reject("cannot safely read selected source %s", rel)
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, 0, reject("cannot safely stat selected source %s", rel)
	}
	if !before.Mode().IsRegular() || linkCount(before) != 1 {
		return nil, 0, reject("selected source is not a single-link regular file: %s", rel)
	}
	mode := before.Mode().Perm()
	if mode != 0644 && mode != 0755 {
		return nil, 0, reject("selected source mode must be 0644 or 0755: %s", rel)
	}
	if before.Size() > MaxFileBytes {
		return nil, 0, reject("selected source exceeds size bound: %s", rel)
	}
	raw, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || int64(len(raw)) != before.Size() || int64(len(raw)) > MaxFileBytes || !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
		return nil, 0, reject("selected source changed while being read: %s", rel)
	}
	if !binary && bytes.IndexByte(raw, 0) >= 0 {
		return nil, 0, reject("binary content is outside the Community source policy: %s", rel)
	}
	if privateKey.Match(raw) {
		return nil, 0, reject("private-key material is forbidden in Community source: %s", rel)
	}
	return raw, mode, nil
}

func externalRead(path string, label string) ([]byte, error) {
	i, err := os.Lstat(path)
	if err != nil || !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 || linkCount(i) != 1 || i.Size() > MaxFileBytes {
		return nil, reject("%s must be a bounded regular single-link file", label)
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, reject("cannot safely read %s", label)
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		return nil, reject("cannot safely read %s", label)
	}
	b, err := io.ReadAll(io.LimitReader(f, MaxFileBytes+1))
	after, statErr := f.Stat()
	if err != nil || statErr != nil || int64(len(b)) != before.Size() || int64(len(b)) > MaxFileBytes || !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
		return nil, reject("%s changed while being read or exceeds its bound", label)
	}
	return b, nil
}
func linkCount(i os.FileInfo) uint64 {
	if st, ok := i.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 0
}

func collect(root string, policy map[string]any, goBin string) (map[string]string, []PackageReceipt, error) {
	moduleRoot := filepath.Join(root, filepath.FromSlash(policy["moduleRoot"].(string)))
	vendor := policy["schemaVersion"] == SchemaV2
	env := baseEnv(vendor)
	verRaw, err := command(goBin, []string{"env", "GOVERSION"}, moduleRoot, env)
	if err != nil {
		return nil, nil, err
	}
	if strings.TrimSpace(string(verRaw)) != policy["requiredGoVersion"] {
		return nil, nil, reject("Go toolchain must be %s, found %s", policy["requiredGoVersion"], strings.TrimSpace(string(verRaw)))
	}
	flag := "-mod=readonly"
	if vendor {
		flag = "-mod=vendor"
	}
	mods, err := command(goBin, []string{"list", flag, "-m"}, moduleRoot, env)
	if err != nil {
		return nil, nil, err
	}
	fields := strings.Fields(string(mods))
	if len(fields) == 0 {
		return nil, nil, reject("go list returned no module")
	}
	modulePath := fields[0]
	if vendor {
		vendRaw, err := os.ReadFile(filepath.Join(moduleRoot, "vendor", "modules.txt"))
		if err != nil {
			return nil, nil, reject("cannot read vendor/modules.txt")
		}
		if err := validateVendorModulesBytes(vendRaw, policy); err != nil {
			return nil, nil, err
		}
	}
	prod := map[string]goPackage{}
	entrypoints, ok := listStrings(policy["entrypoints"])
	if !ok || len(entrypoints) == 0 {
		return nil, nil, reject("policy entrypoints are invalid")
	}
	targets, _ := listStrings(policy["sourceBuildTargets"])
	for _, target := range targets {
		parts := strings.SplitN(target, "/", 2)
		args := []string{"list", "-json", "-deps"}
		args = append(args, entrypoints...)
		raw, err := command(goBin, args, moduleRoot, baseEnv(vendor, "GOOS="+parts[0], "GOARCH="+parts[1]))
		if err != nil {
			return nil, nil, err
		}
		ps, err := decodeStream(raw)
		if err != nil {
			return nil, nil, reject("go list returned invalid JSON: %v", err)
		}
		for _, p := range ps {
			if inModule(p, modulePath) {
				prod[p.ImportPath] = mergePackage(prod[p.ImportPath], p, false)
			}
		}
	}
	if len(prod) == 0 {
		return nil, nil, reject("entrypoint produced no in-module Go package closure")
	}
	// `go list -test` exposes direct tests and test-only in-module support
	// packages. Merge all target/tag variants before selecting files so the
	// manifest covers the complete source-build closure.
	imports := make([]string, 0, len(prod))
	for p := range prod {
		imports = append(imports, p)
	}
	sort.Strings(imports)
	testPackages := map[string]goPackage{}
	testSupport := map[string]goPackage{}
	for _, target := range targets {
		parts := strings.SplitN(target, "/", 2)
		for _, variant := range [][]string{{}, {"-tags", "parityreview"}} {
			args := []string{"list", "-json", "-deps", "-test"}
			args = append(args, variant...)
			args = append(args, imports...)
			raw, err := command(goBin, args, moduleRoot, baseEnv(vendor, "GOOS="+parts[0], "GOARCH="+parts[1]))
			if err != nil {
				return nil, nil, err
			}
			ps, err := decodeStream(raw)
			if err != nil {
				return nil, nil, reject("go list returned invalid JSON: %v", err)
			}
			for _, p := range ps {
				if !inModule(p, modulePath) || strings.Contains(p.ImportPath, " [") || strings.HasSuffix(p.ImportPath, ".test") {
					continue
				}
				if _, exists := prod[p.ImportPath]; exists {
					testPackages[p.ImportPath] = mergePackage(testPackages[p.ImportPath], p, true)
				} else if p.ForTest == "" {
					testSupport[p.ImportPath] = mergePackage(testSupport[p.ImportPath], p, false)
				}
			}
		}
	}
	files := map[string]string{}
	receipts := []PackageReceipt{}
	for _, p := range prod {
		rel, err := filepath.Rel(root, p.Dir)
		if err != nil {
			return nil, nil, err
		}
		rel = filepath.ToSlash(rel)
		for _, n := range append(append(append(append(append(append(append(append(append(append(append([]string{}, p.GoFiles...), p.CgoFiles...), p.CFiles...), p.CXXFiles...), p.MFiles...), p.HFiles...), p.FFiles...), p.SFiles...), p.SwigFiles...), p.SwigCXXFiles...), p.SysoFiles...) {
			addFile(files, rel+"/"+n, "production-go")
		}
		for _, n := range p.EmbedFiles {
			addFile(files, rel+"/"+n, "production-embed")
		}
		tests := directTests(testPackages[p.ImportPath])
		if len(tests) == 0 {
			return nil, nil, reject("production packages without direct tests: %s", p.ImportPath)
		}
		for _, n := range tests {
			addFile(files, rel+"/"+n, "test-go")
		}
		for _, n := range append(append([]string{}, testPackages[p.ImportPath].TestEmbedFiles...), testPackages[p.ImportPath].XTestEmbedFiles...) {
			addFile(files, rel+"/"+n, "testdata")
		}
		if err := collectPackageTestdata(root, rel, files); err != nil {
			return nil, nil, err
		}
		receipts = append(receipts, PackageReceipt{ImportPath: p.ImportPath, Name: p.Name, Path: rel, DirectTests: tests})
	}
	for _, p := range testSupport {
		rel, err := filepath.Rel(root, p.Dir)
		if err != nil {
			return nil, nil, err
		}
		rel = filepath.ToSlash(rel)
		for _, n := range append(append(append(append(append(append(append(append(append(append(append([]string{}, p.GoFiles...), p.CgoFiles...), p.CFiles...), p.CXXFiles...), p.MFiles...), p.HFiles...), p.FFiles...), p.SFiles...), p.SwigFiles...), p.SwigCXXFiles...), p.SysoFiles...) {
			addFile(files, rel+"/"+n, "test-support-go")
		}
		for _, n := range p.EmbedFiles {
			addFile(files, rel+"/"+n, "test-support-embed")
		}
	}
	sort.Slice(receipts, func(i, j int) bool { return receipts[i].ImportPath < receipts[j].ImportPath })
	for _, x := range policy["requiredPaths"].([]any) {
		m := x.(map[string]any)
		p := m["path"].(string)
		role := m["role"].(string)
		if rec, ok := m["recursive"].(bool); ok && rec {
			if err := collectRequiredDirectory(root, p, role, files); err != nil {
				return nil, nil, reject("required directory is unsafe: %s", p)
			}
		} else {
			addFile(files, p, role)
		}
	}
	addFile(files, filepath.ToSlash(filepath.Join(policy["moduleRoot"].(string), "go.mod")), "module")
	if _, err := os.Stat(filepath.Join(moduleRoot, "go.sum")); err == nil {
		addFile(files, filepath.ToSlash(filepath.Join(policy["moduleRoot"].(string), "go.sum")), "module")
	}
	return files, receipts, nil
}

func collectRequiredDirectory(root, relative, role string, files map[string]string) error {
	base := filepath.Join(root, filepath.FromSlash(relative))
	return filepath.Walk(base, func(name string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if name == base {
			if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return reject("required directory is unsafe")
			}
			return nil
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
			return reject("required directory contains a non-regular entry")
		}
		if info.Mode().IsRegular() {
			rel, relErr := filepath.Rel(root, name)
			if relErr != nil {
				return relErr
			}
			addFile(files, filepath.ToSlash(rel), role)
		}
		return nil
	})
}

func collectPackageTestdata(root, packagePath string, files map[string]string) error {
	relative := filepath.ToSlash(filepath.Join(packagePath, "testdata"))
	info, err := os.Lstat(filepath.Join(root, filepath.FromSlash(relative)))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return reject("package testdata directory is unsafe: %s", packagePath)
	}
	return collectRequiredDirectory(root, relative, "testdata", files)
}

func mergePackage(old, next goPackage, tests bool) goPackage {
	if old.ImportPath == "" {
		old = next
	}
	old.GoFiles = union(old.GoFiles, next.GoFiles)
	old.CgoFiles = union(old.CgoFiles, next.CgoFiles)
	old.CFiles = union(old.CFiles, next.CFiles)
	old.CXXFiles = union(old.CXXFiles, next.CXXFiles)
	old.MFiles = union(old.MFiles, next.MFiles)
	old.HFiles = union(old.HFiles, next.HFiles)
	old.FFiles = union(old.FFiles, next.FFiles)
	old.SFiles = union(old.SFiles, next.SFiles)
	old.SwigFiles = union(old.SwigFiles, next.SwigFiles)
	old.SwigCXXFiles = union(old.SwigCXXFiles, next.SwigCXXFiles)
	old.SysoFiles = union(old.SysoFiles, next.SysoFiles)
	old.EmbedFiles = union(old.EmbedFiles, next.EmbedFiles)
	if tests {
		old.TestGoFiles = union(old.TestGoFiles, next.TestGoFiles)
		old.XTestGoFiles = union(old.XTestGoFiles, next.XTestGoFiles)
		old.TestEmbedFiles = union(old.TestEmbedFiles, next.TestEmbedFiles)
		old.XTestEmbedFiles = union(old.XTestEmbedFiles, next.XTestEmbedFiles)
	}
	return old
}
func union(a, b []string) []string {
	m := map[string]bool{}
	for _, x := range append(a, b...) {
		m[x] = true
	}
	out := make([]string, 0, len(m))
	for x := range m {
		out = append(out, x)
	}
	sort.Strings(out)
	return out
}

// directTests includes both same-package and external-package Go tests. Both
// forms are direct tests of the production package and must be exported.
func directTests(p goPackage) []string {
	return union(p.TestGoFiles, p.XTestGoFiles)
}

func derive(o Options) (Manifest, map[string][]byte, error) {
	root, err := filepath.Abs(o.SourceRoot)
	if err != nil {
		return Manifest{}, nil, err
	}
	pp, err := filepath.Abs(o.PolicyPath)
	if err != nil {
		return Manifest{}, nil, err
	}
	rel, err := filepath.Rel(root, pp)
	if err != nil {
		return Manifest{}, nil, err
	}
	raw, _, err := stableRead(root, filepath.ToSlash(rel), false)
	if err != nil {
		return Manifest{}, nil, err
	}
	v, err := decodeStrict(raw)
	if err != nil {
		return Manifest{}, nil, reject("policy is not strict JSON: %v", err)
	}
	policy, err := object(v)
	if err != nil {
		return Manifest{}, nil, err
	}
	policy, err = validatePolicy(policy)
	if err != nil {
		return Manifest{}, nil, err
	}
	if policy["schemaVersion"] == SchemaV2 {
		if err := validateVendorTree(root, policy); err != nil {
			return Manifest{}, nil, err
		}
		if err := validateModuleSums(root, policy); err != nil {
			return Manifest{}, nil, err
		}
	}
	files, pkg, err := collect(root, policy, o.Go)
	if err != nil {
		return Manifest{}, nil, err
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	entries := []FileEntry{}
	blobs := map[string][]byte{}
	var total int64
	for _, p := range paths {
		binary := false
		if rs, ok := policy["binaryResources"].([]any); ok {
			for _, x := range rs {
				m := x.(map[string]any)
				if m["path"] == p {
					binary = true
				}
			}
		}
		b, mode, err := stableRead(root, p, binary)
		if err != nil {
			return Manifest{}, nil, err
		}
		total += int64(len(b))
		if total > MaxTotalBytes {
			return Manifest{}, nil, reject("selected Community source exceeds total size bound")
		}
		blobs[p] = b
		h := sha256.Sum256(b)
		entries = append(entries, FileEntry{Mode: fmt.Sprintf("%04o", mode.Perm()), Path: p, Role: files[p], SHA256: hex.EncodeToString(h[:]), Size: int64(len(b))})
	}
	if policy["schemaVersion"] == SchemaV2 {
		if err := validateCapturedV2Bindings(entries, blobs, policy, filepath.ToSlash(rel), raw); err != nil {
			return Manifest{}, nil, err
		}
	}
	m := Manifest{SchemaVersion: ManifestSchema, BinaryName: policy["binaryName"].(string), BuildTargets: mustStrings(policy["buildTargets"]), SourceBuildTargets: mustStrings(policy["sourceBuildTargets"]), Entrypoints: mustStrings(policy["entrypoints"]), ModuleRoot: policy["moduleRoot"].(string), TestTags: []string{"parityreview"}, Files: entries, Packages: pkg, PolicyDigest: digest(raw), RequiredGoVersion: policy["requiredGoVersion"].(string), ToolchainArchives: mustStringMap(policy["toolchainArchives"])}
	if policy["schemaVersion"] == SchemaV2 {
		m.ModuleMode = "vendor"
		m.VendorTreeDigest = policy["vendorTreeDigest"].(string)
		for _, x := range policy["externalModules"].([]any) {
			n := x.(map[string]any)
			m.ExternalModules = append(m.ExternalModules, ExternalModuleReceipt{Path: n["path"].(string), Version: n["version"].(string), ModuleSum: n["moduleSum"].(string), GoModSum: n["goModSum"].(string), LicenseDeclared: n["licenseDeclared"].(string)})
		}
		for _, x := range policy["binaryResources"].([]any) {
			n := x.(map[string]any)
			m.BinaryResources = append(m.BinaryResources, BinaryResource{Path: n["path"].(string), SHA256: n["sha256"].(string)})
		}
	}
	tmp := m
	tmp.ManifestDigest = ""
	tb, _ := canonical(tmp)
	m.ManifestDigest = digest(tb)
	return m, blobs, nil
}
func mustStrings(v any) []string { a, _ := listStrings(v); return a }
func mustStringMap(v any) map[string]string {
	m := map[string]string{}
	for k, x := range v.(map[string]any) {
		m[k] = x.(string)
	}
	return m
}

func Generate(o Options) (Manifest, error) {
	m, _, err := derive(o)
	if err != nil {
		return Manifest{}, err
	}
	if o.OutputPath == "" {
		return m, nil
	}
	out, err := resolveOutputOutside(o.SourceRoot, o.OutputPath)
	if err != nil {
		return Manifest{}, err
	}
	o.OutputPath = out
	b, err := canonical(m)
	if err != nil {
		return Manifest{}, err
	}
	f, err := createExclusive(o.OutputPath)
	if err != nil {
		return Manifest{}, reject("refusing to overwrite output: %v", err)
	}
	defer f.Close()
	if _, err = f.Write(b); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

func createExclusive(path string) (*os.File, error) {
	parent, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return parent.OpenFile(filepath.Base(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
}

func resolveOutputOutside(sourceRoot, output string) (string, error) {
	root, err := filepath.Abs(sourceRoot)
	if err != nil {
		return "", reject("source root is invalid")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", reject("source root is invalid")
	}
	out, err := filepath.Abs(output)
	if err != nil {
		return "", reject("generated manifest output is invalid")
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(out))
	if err != nil {
		return "", reject("generated manifest output parent is invalid")
	}
	out = filepath.Join(parent, filepath.Base(out))
	root = physicalPath(root)
	out = physicalPath(out)
	if out == root || strings.HasPrefix(out, root+string(filepath.Separator)) {
		return "", reject("generated manifest output must be outside the source root")
	}
	return out, nil
}

func physicalPath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return filepath.Clean(resolved)
	}
	parent := filepath.Dir(path)
	resolvedParent, err := filepath.EvalSymlinks(parent)
	if err != nil {
		return filepath.Clean(path)
	}
	return filepath.Join(resolvedParent, filepath.Base(path))
}
func Verify(o Options) (Manifest, error) {
	m, _, err := derive(o)
	if err != nil {
		return Manifest{}, err
	}
	raw, err := externalRead(o.ManifestPath, "manifest")
	if err != nil {
		return Manifest{}, err
	}
	v, err := decodeStrict(raw)
	if err != nil {
		return Manifest{}, reject("manifest is not strict JSON: %v", err)
	}
	can, _ := canonical(v)
	if !bytes.Equal(raw, can) {
		return Manifest{}, reject("manifest is not canonical JSON")
	}
	want, _ := canonical(m)
	if !bytes.Equal(raw, want) {
		return Manifest{}, reject("manifest differs from the exact current policy and source bytes")
	}
	return m, nil
}
func Stage(o Options) (Manifest, error) {
	m, blobs, err := derive(o)
	if err != nil {
		return Manifest{}, err
	}
	raw, err := externalRead(o.ManifestPath, "manifest")
	if err != nil {
		return Manifest{}, err
	}
	want, _ := canonical(m)
	if !bytes.Equal(raw, want) {
		return Manifest{}, reject("manifest differs from the exact current policy and source bytes")
	}
	if o.OutputPath == "" {
		return Manifest{}, reject("stage output is required")
	}
	out, err := resolveOutputOutside(o.SourceRoot, o.OutputPath)
	if err != nil {
		return Manifest{}, err
	}
	o.OutputPath = out
	parent := filepath.Dir(o.OutputPath)
	name := filepath.Base(o.OutputPath)
	if name == "." || name == string(filepath.Separator) || name == "" {
		return Manifest{}, reject("stage output name is invalid")
	}
	parentRoot, err := os.OpenRoot(parent)
	if err != nil {
		return Manifest{}, reject("stage output parent is unavailable")
	}
	defer parentRoot.Close()
	if err := parentRoot.Mkdir(name, 0700); err != nil {
		return Manifest{}, reject("refusing to overwrite stage")
	}
	stageRoot, err := parentRoot.OpenRoot(name)
	if err != nil {
		_ = parentRoot.RemoveAll(name)
		return Manifest{}, reject("cannot safely open stage")
	}
	defer stageRoot.Close()
	complete := false
	defer func() {
		if !complete {
			_ = parentRoot.RemoveAll(name)
		}
	}()
	for _, e := range m.Files {
		parts := strings.Split(e.Path, "/")
		for i := 1; i < len(parts); i++ {
			dir := strings.Join(parts[:i], "/")
			if err := stageRoot.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
				return Manifest{}, err
			}
		}
		if err := writeStageFile(stageRoot, e, blobs[e.Path]); err != nil {
			return Manifest{}, err
		}
	}
	if o.RunNativeChecks {
		if err := RunNativeChecks(o.OutputPath, m, o.Go); err != nil {
			return Manifest{}, err
		}
	}
	complete = true
	return m, nil
}
func writeStageFile(root *os.Root, entry FileEntry, blob []byte) error {
	f, err := root.OpenFile(entry.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, os.FileMode(parseMode(entry.Mode)))
	if err != nil {
		return err
	}
	if _, err := f.Write(blob); err != nil {
		_ = f.Close()
		return err
	}
	// OpenFile honors a caller umask. Reset the declared source mode explicitly
	// so the staged bytes and modes match the manifest under restrictive umasks.
	if err := f.Chmod(os.FileMode(parseMode(entry.Mode))); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func parseMode(s string) uint32 {
	var n uint32
	for _, c := range s {
		n = n*8 + uint32(c-'0')
	}
	return n
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// RunNativeChecks runs the bounded Go source-stage checks and declared
// release cross-builds. It never executes downloaded artifacts.
func RunNativeChecks(stage string, manifest Manifest, goBin string) error {
	moduleRel, err := safeRelative(manifest.ModuleRoot, "manifest module root")
	if err != nil {
		return err
	}
	if len(manifest.Entrypoints) == 0 {
		return reject("native checks require declared entrypoints")
	}
	moduleRoot := filepath.Join(stage, filepath.FromSlash(moduleRel))
	st, err := os.Stat(moduleRoot)
	if err != nil || !st.IsDir() {
		return reject("staged module root is unavailable")
	}
	env := baseEnv(manifest.ModuleMode == "vendor")
	hostRaw, err := command(goBin, []string{"env", "GOHOSTOS", "GOHOSTARCH"}, moduleRoot, env)
	if err != nil {
		return err
	}
	hostFields := strings.Fields(string(hostRaw))
	if len(hostFields) != 2 || !containsString(manifest.SourceBuildTargets, hostFields[0]+"/"+hostFields[1]) {
		return reject("native host is outside the declared source-build targets")
	}
	if _, err := command(goBin, []string{"vet", "./..."}, moduleRoot, env); err != nil {
		return err
	}
	if _, err := command(goBin, []string{"test", "./...", "-count=1"}, moduleRoot, env); err != nil {
		return err
	}
	for _, tag := range manifest.TestTags {
		if _, err := command(goBin, []string{"test", "-tags", tag, "./...", "-count=1"}, moduleRoot, env); err != nil {
			return err
		}
	}
	work, err := os.MkdirTemp("", "community-cross-build.")
	if err != nil {
		return err
	}
	defer os.RemoveAll(work)
	for _, target := range manifest.BuildTargets {
		parts := strings.SplitN(target, "/", 2)
		if len(parts) != 2 {
			return reject("invalid build target")
		}
		for i, entrypoint := range manifest.Entrypoints {
			out := filepath.Join(work, fmt.Sprintf("%s-%s-%s-%d", manifest.BinaryName, parts[0], parts[1], i))
			args := []string{"build", "-trimpath", "-buildvcs=false", "-o", out, entrypoint}
			if _, err := command(goBin, args, moduleRoot, baseEnv(manifest.ModuleMode == "vendor", "GOOS="+parts[0], "GOARCH="+parts[1])); err != nil {
				return err
			}
		}
	}
	return nil
}

func containsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
