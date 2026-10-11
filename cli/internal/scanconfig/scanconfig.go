// SPDX-License-Identifier: AGPL-3.0-only

// Package scanconfig reads the repository declaration file prufyx.yaml: a
// closed, versioned schema of inputs, versions and declarations that a scan
// would otherwise take from command-line flags.
//
// Parsing is strict. Unknown keys, a second document, template syntax, YAML
// anchors and aliases, duplicate keys and malformed values are errors, and no
// error echoes file contents beyond a short key path.
package scanconfig

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/intake"
)

const (
	// FileName is the name Discover looks for.
	FileName = "prufyx.yaml"
	// APIVersion and Kind identify a configuration document.
	APIVersion = "prufyx.io/v1alpha1"
	Kind       = "ScanConfig"
	// MaxBytes bounds the configuration file.
	MaxBytes = 64 << 10
	// MaxInputs bounds the inputs list.
	MaxInputs = 64

	maxMessage = 256
	maxKeyEcho = 48
)

// ErrConfig is wrapped by every error that rejects a configuration file's
// contents. Read and permission failures wrap the intake errors instead.
var ErrConfig = errors.New("invalid scan configuration")

// Config is a parsed configuration file. A nil pointer or map means the key was
// absent; an absent declaration is never defaulted.
type Config struct {
	// Digest is sha256:<hex> of the raw file bytes.
	Digest       string
	Inputs       []string
	Current      map[string]string
	Target       map[string]string
	Declarations DeclarationSet
}

// DeclarationSet holds the declarations by project. Later versions add
// projects and keys additively.
type DeclarationSet struct {
	Kubernetes *KubernetesDeclarations
}

// KubernetesDeclarations maps to the flags of the Kubernetes native route.
type KubernetesDeclarations struct {
	Distribution          *string
	ResourceScopeComplete *bool
	TargetApplyRequired   *bool
}

// IsConfigDocument reports whether a document identity is that of a
// configuration file, so an intake of a directory can drop it.
func IsConfigDocument(apiVersion, kind string) bool {
	return apiVersion == APIVersion && kind == Kind
}

// Digest returns sha256:<hex> of the raw file bytes.
func Digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

type configError struct{ msg string }

func (e *configError) Error() string { return e.msg }
func (e *configError) Unwrap() error { return ErrConfig }

// fail builds a bounded, deterministic error. Pieces taken from the file are
// quoted and cut to a short length by echo.
func fail(format string, args ...any) error {
	msg := "scan configuration: " + fmt.Sprintf(format, args...)
	if len(msg) > maxMessage {
		msg = strings.ToValidUTF8(msg[:maxMessage], "")
	}
	return &configError{msg}
}

// echo quotes text taken from the file after cutting it to a short length.
func echo(text string) string {
	if len(text) > maxKeyEcho {
		text = strings.ToValidUTF8(text[:maxKeyEcho], "") + "..."
	}
	return strconv.Quote(text)
}

// Parse reads one configuration file's bytes.
func Parse(raw []byte) (Config, error) {
	if len(raw) > MaxBytes {
		return Config{}, fail("file is larger than %d bytes", MaxBytes)
	}
	if len(raw) == 0 || !utf8.Valid(raw) {
		return Config{}, fail("file is empty or not UTF-8")
	}
	text := string(raw)
	if strings.Contains(text, "{{") || strings.Contains(text, "${") {
		return Config{}, fail("template syntax is not accepted")
	}
	documents, err := intake.DecodeDocuments(raw)
	if err != nil {
		return Config{}, fail("file is not a plain YAML document")
	}
	if len(documents) != 1 {
		return Config{}, fail("expected exactly one document, found %d", len(documents))
	}
	root, ok := documents[0].(map[string]any)
	if !ok {
		return Config{}, fail("document is not a mapping")
	}
	if err := checkFolded(root, ""); err != nil {
		return Config{}, err
	}
	cfg, err := build(root)
	if err != nil {
		return Config{}, err
	}
	cfg.Digest = Digest(raw)
	return cfg, nil
}

// checkFolded rejects keys that differ only in case anywhere in the document.
func checkFolded(value any, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		seen := map[string]bool{}
		for _, key := range sortedKeys(typed) {
			folded := strings.ToLower(key)
			if seen[folded] {
				return fail("keys differing only in case at %s", echo(join(path, key)))
			}
			seen[folded] = true
			if err := checkFolded(typed[key], join(path, key)); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range typed {
			if err := checkFolded(child, path); err != nil {
				return err
			}
		}
	}
	return nil
}

func join(path, key string) string {
	if path == "" {
		return key
	}
	return path + "." + key
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

// object checks that value is a mapping whose keys are all in allowed.
func object(value any, path string, allowed ...string) (map[string]any, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fail("%s must be a mapping", echo(path))
	}
	for _, key := range sortedKeys(m) {
		known := false
		for _, name := range allowed {
			known = known || key == name
		}
		if !known {
			return nil, fail("unknown key %s", echo(join(path, key)))
		}
	}
	return m, nil
}

func build(root map[string]any) (Config, error) {
	m, err := object(root, "", "apiVersion", "kind", "inputs", "current", "target", "declarations")
	if err != nil {
		return Config{}, err
	}
	if v, _ := m["apiVersion"].(string); v != APIVersion {
		return Config{}, fail("apiVersion must be %s", APIVersion)
	}
	if v, _ := m["kind"].(string); v != Kind {
		return Config{}, fail("kind must be %s", Kind)
	}
	var cfg Config
	if v, present := m["inputs"]; present {
		if cfg.Inputs, err = parseInputs(v); err != nil {
			return Config{}, err
		}
	}
	if v, present := m["current"]; present {
		if cfg.Current, err = parseVersions(v, "current"); err != nil {
			return Config{}, err
		}
	}
	if v, present := m["target"]; present {
		if cfg.Target, err = parseVersions(v, "target"); err != nil {
			return Config{}, err
		}
	}
	if v, present := m["declarations"]; present {
		if cfg.Declarations, err = parseDeclarations(v); err != nil {
			return Config{}, err
		}
	}
	return cfg, nil
}

func parseInputs(value any) ([]string, error) {
	list, ok := value.([]any)
	if !ok {
		return nil, fail("inputs must be a list")
	}
	if len(list) == 0 || len(list) > MaxInputs {
		return nil, fail("inputs must have 1 to %d entries", MaxInputs)
	}
	out := make([]string, 0, len(list))
	for index, item := range list {
		path, ok := item.(string)
		if !ok {
			return nil, fail("inputs[%d] must be a string", index)
		}
		if !safeRelative(path) {
			return nil, fail("inputs[%d] must be a clean relative path without ..", index)
		}
		out = append(out, path)
	}
	return out, nil
}

// safeRelative accepts a clean relative path with no .. element, optionally
// with one trailing slash.
func safeRelative(path string) bool {
	if path == "" || strings.ContainsRune(path, 0) || filepath.IsAbs(path) || strings.HasPrefix(path, "/") || strings.Contains(path, `\`) {
		return false
	}
	// One trailing slash marks a directory ("rendered/"); everything else
	// must already be in clean form.
	bare := strings.TrimSuffix(path, "/")
	if bare == "" || filepath.Clean(bare) != bare {
		return false
	}
	for _, element := range strings.Split(bare, "/") {
		if element == ".." {
			return false
		}
	}
	return true
}

func parseVersions(value any, path string) (map[string]string, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fail("%s must be a mapping", path)
	}
	out := make(map[string]string, len(m))
	for _, slug := range sortedKeys(m) {
		// A community project of the reviewed table is named too: whether the
		// knowledge holds data for it is decided by the scan, which refuses
		// one without data with the community catalog message.
		if _, err := cncfcheck.Component(slug); err != nil && !cncfcheck.IsCommunityProject(slug) {
			return nil, fail("unknown project %s under %s", echo(slug), path)
		}
		version, ok := m[slug].(string)
		if !ok || !validVersion(version) {
			return nil, fail("%s must be a version X.Y.Z", echo(join(path, slug)))
		}
		out[slug] = version
	}
	return out, nil
}

// validVersion accepts X.Y.Z with decimal parts, no leading zeros, no prefix
// and no suffix: the grammar the engine uses.
func validVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 9 || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func parseDeclarations(value any) (DeclarationSet, error) {
	m, err := object(value, "declarations", "kubernetes")
	if err != nil {
		return DeclarationSet{}, err
	}
	var set DeclarationSet
	if v, present := m["kubernetes"]; present {
		k, err := object(v, "declarations.kubernetes", "distribution", "resourceScopeComplete", "targetApplyRequired")
		if err != nil {
			return DeclarationSet{}, err
		}
		decl := &KubernetesDeclarations{}
		if v, present := k["distribution"]; present {
			s, ok := v.(string)
			if !ok || (s != DistributionOfficialUpstream && s != DistributionCustomBuild) {
				return DeclarationSet{}, fail("declarations.kubernetes.distribution must be %s or %s", DistributionOfficialUpstream, DistributionCustomBuild)
			}
			decl.Distribution = &s
		}
		for _, field := range []struct {
			name string
			dst  **bool
		}{{"resourceScopeComplete", &decl.ResourceScopeComplete}, {"targetApplyRequired", &decl.TargetApplyRequired}} {
			if v, present := k[field.name]; present {
				b, ok := v.(bool)
				if !ok {
					return DeclarationSet{}, fail("declarations.kubernetes.%s must be true or false", field.name)
				}
				*field.dst = &b
			}
		}
		set.Kubernetes = decl
	}
	return set, nil
}

// Load reads and parses a configuration file. The file is opened through the
// intake permission policy (descriptor-safe, regular file, not a symlink, at
// most MaxBytes), then its bytes are read once more and must match the digest
// intake recorded, so the parsed bytes are the bytes the policy approved.
// Stdin is not accepted. Config.Digest is the digest of the bytes read.
func Load(path string, policy intake.PermissionPolicy) (Config, error) {
	if path == "" || path == "-" {
		return Config{}, fail("a configuration file path is required")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return Config{}, fmt.Errorf("%w: %s", intake.ErrInput, "configuration file cannot be read")
	}
	if !info.Mode().IsRegular() {
		return Config{}, fail("configuration path is not a regular file")
	}
	workspace, err := intake.Open([]string{path}, intake.Options{
		Permissions: policy,
		Limits:      intake.Limits{FileBytes: MaxBytes, Files: 1, Documents: 1},
	})
	if err != nil {
		return Config{}, err
	}
	if len(workspace.Files) != 1 || len(workspace.Omissions) != 0 {
		return Config{}, fail("configuration file was not read as one plain document")
	}
	raw, err := readBounded(path)
	if err != nil {
		return Config{}, err
	}
	if Digest(raw) != workspace.Files[0].Digest {
		return Config{}, fail("file changed while it was read")
	}
	cfg, err := Parse(raw)
	if err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func readBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", intake.ErrInput, "configuration file cannot be read")
	}
	defer file.Close()
	buf := make([]byte, MaxBytes+1)
	n := 0
	for n < len(buf) {
		m, err := file.Read(buf[n:])
		n += m
		if err != nil {
			break
		}
	}
	if n > MaxBytes {
		return nil, fail("file is larger than %d bytes", MaxBytes)
	}
	return buf[:n], nil
}

// Discover looks for FileName next to the first input: in the input itself
// when it is a directory, else in its parent directory. It never walks up.
// A missing file (or a missing or stdin input) is not an error; a file that
// exists but cannot be examined is.
func Discover(firstInput string) (string, bool, error) {
	if firstInput == "" {
		return "", false, fail("an input path is required")
	}
	if firstInput == "-" {
		return "", false, nil
	}
	dir := firstInput
	info, err := os.Stat(firstInput)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "", false, nil
	case err != nil:
		return "", false, fmt.Errorf("%w: %s", intake.ErrInput, "input cannot be examined")
	case !info.IsDir():
		dir = filepath.Dir(firstInput)
	}
	candidate := filepath.Join(dir, FileName)
	if _, err := os.Lstat(candidate); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("%w: %s", intake.ErrInput, "configuration file cannot be examined")
	}
	return candidate, true, nil
}
