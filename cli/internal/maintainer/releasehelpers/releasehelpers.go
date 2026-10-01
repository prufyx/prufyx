// SPDX-License-Identifier: AGPL-3.0-only

// Package releasehelpers contains local, deterministic checks used by the
// Community release shell. It has no network, signing, publishing, or runtime
// mutation authority.
package releasehelpers

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

var ErrRejected = errors.New("release helper input rejected")

type HelperError struct{ Message string }

func (e *HelperError) Error() string  { return e.Message }
func reject(f string, a ...any) error { return &HelperError{fmt.Sprintf(f, a...)} }

type MetadataOptions struct{ Output, Version, Revision, SourceTreeDigest, ManifestDigest, Target, BuildEpoch, GoVersion string }
type VersionOptions struct {
	Metadata, ReportFile string
	Report               []byte
}
type ArchiveOptions struct{ Archive, PackageName, RepositoryRoot, BuildEpoch string }
type SBOMOptions struct {
	Output, Version, Revision, BuildEpoch, GoVersion, Policy string
	// ArtifactDir and Artifacts bind the SBOM to the exact final release
	// artifacts. When supplied, the document gains an analyzed file inventory
	// with a SHA-256 and SHA-1 per artifact and an SPDX package verification
	// code, so the SBOM describes shipped bytes rather than intent alone.
	ArtifactDir string
	Artifacts   []string
}

// sbomFile is one analyzed final release artifact.
type sbomFile struct {
	name, sha256, sha1 string
}
type SmokeReceiptOptions struct{ Version, Target, ArchiveDigest, Metadata string }

const (
	maxArchiveCompressed   int64 = 640 << 20
	maxArchiveUncompressed int64 = 512 << 20
	maxArchiveMembers            = 4096
)

func canonical(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, e
	}
	return append(b, '\n'), nil
}
func readJSON(path, label string) (map[string]any, error) {
	b, e := safeRead(path, 32<<20)
	if e != nil {
		return nil, reject("cannot read %s", label)
	}
	return decodeObject(b, label)
}
func safeRead(path string, max int64) ([]byte, error) {
	i, e := os.Lstat(path)
	if e != nil || !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 || i.Size() > max {
		return nil, ErrRejected
	}
	if st, ok := i.Sys().(*syscall.Stat_t); ok && st.Nlink != 1 {
		return nil, ErrRejected
	}
	f, e := openBoundedRead(path)
	if e != nil {
		return nil, ErrRejected
	}
	defer f.Close()
	before, e := f.Stat()
	if e != nil {
		return nil, ErrRejected
	}
	b, e := io.ReadAll(io.LimitReader(f, max+1))
	after, _ := f.Stat()
	if e != nil || int64(len(b)) != before.Size() || int64(len(b)) > max || !os.SameFile(before, after) || before.ModTime() != after.ModTime() {
		return nil, ErrRejected
	}
	if st, ok := after.Sys().(*syscall.Stat_t); ok && st.Nlink != 1 {
		return nil, ErrRejected
	}
	return b, nil
}
func decodeObject(b []byte, label string) (map[string]any, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	v, e := decodeValue(d, 0)
	if e != nil {
		return nil, reject("%s is not strict JSON", label)
	}
	var extra any
	if e := d.Decode(&extra); e != io.EOF {
		return nil, reject("%s has trailing JSON", label)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, reject("%s must be an object", label)
	}
	return m, nil
}

func decodeValue(d *json.Decoder, depth int) (any, error) {
	if depth > 128 {
		return nil, errors.New("JSON nesting limit exceeded")
	}
	t, err := d.Token()
	if err != nil {
		return nil, err
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				keyToken, err := d.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("object key is not string")
				}
				if _, exists := m[key]; exists {
					return nil, errors.New("duplicate JSON key")
				}
				value, err := decodeValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				m[key] = value
			}
			_, err = d.Token()
			return m, err
		case '[':
			values := []any{}
			for d.More() {
				value, err := decodeValue(d, depth+1)
				if err != nil {
					return nil, err
				}
				values = append(values, value)
			}
			_, err = d.Token()
			return values, err
		}
	}
	switch t.(type) {
	case string, json.Number, bool, nil:
		return t, nil
	}
	return nil, errors.New("invalid JSON value")
}
func decimal(s string) (int64, error) {
	if s == "" {
		return 0, reject("invalid integer")
	}
	n, e := strconv.ParseInt(s, 10, 64)
	if e != nil || n < 0 {
		return 0, reject("invalid integer")
	}
	return n, nil
}

func exactObjectKeys(m map[string]any, keys ...string) bool {
	wanted := make(map[string]bool, len(keys))
	for _, key := range keys {
		wanted[key] = true
	}
	if len(m) != len(wanted) {
		return false
	}
	for key := range m {
		if !wanted[key] {
			return false
		}
	}
	return true
}

func validH1(value string) bool {
	if !strings.HasPrefix(value, "h1:") {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(value, "h1:"))
	return err == nil && len(decoded) == 32
}

func validSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func validPolicyPath(value, prefix string) bool {
	if value == "" || !strings.HasPrefix(value, prefix) || strings.ContainsAny(value, "\\\r\n") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." {
			return false
		}
	}
	return true
}

func policyModules(policy map[string]any) ([]map[string]string, error) {
	if !exactObjectKeys(policy,
		"allowExternalModules", "binaryName", "binaryResources", "buildTargets", "entrypoints",
		"externalModules", "moduleRoot", "requiredGoVersion", "requiredPaths", "schemaVersion",
		"sourceBuildTargets", "testPolicy", "toolchainArchives", "vendorRoot", "vendorTreeDigest",
	) {
		return nil, reject("shipping policy has an unknown or missing field")
	}
	if policy["schemaVersion"] != "prufyx.io/community-shipping-policy/v2" || policy["allowExternalModules"] != true {
		return nil, reject("SBOM requires the active v2 shipping policy")
	}
	raw, ok := policy["externalModules"].([]any)
	if !ok || len(raw) == 0 {
		return nil, reject("shipping policy externalModules must be a non-empty array")
	}
	modules := make([]map[string]string, 0, len(raw))
	lastPath := ""
	noticeDestinations := map[string]bool{}
	for _, item := range raw {
		module, ok := item.(map[string]any)
		if !ok || !exactObjectKeys(module, "path", "version", "moduleSum", "goModSum", "licenseDeclared", "notices") {
			return nil, reject("shipping policy external module has an invalid schema")
		}
		path, pathOK := module["path"].(string)
		version, versionOK := module["version"].(string)
		moduleSum, moduleSumOK := module["moduleSum"].(string)
		goModSum, goModSumOK := module["goModSum"].(string)
		license, licenseOK := module["licenseDeclared"].(string)
		invalidProfile := !pathOK || !versionOK || !validPolicyPath(path, "") ||
			strings.ContainsAny(path, " \t\r\n") || strings.ContainsAny(version, " \t\r\n") ||
			!moduleSumOK || !goModSumOK || !validH1(moduleSum) || !validH1(goModSum) ||
			!licenseOK || license == "" || strings.ContainsAny(license, "\r\n") ||
			(lastPath != "" && path <= lastPath)
		if invalidProfile {
			return nil, reject("shipping policy external module profile is invalid or unsorted")
		}
		lastPath = path
		notices, ok := module["notices"].([]any)
		if !ok || len(notices) == 0 {
			return nil, reject("shipping policy external module has no notices")
		}
		for _, item := range notices {
			notice, ok := item.(map[string]any)
			if !ok || !exactObjectKeys(notice, "sourcePath", "distributionPath", "sha256") {
				return nil, reject("shipping policy external module notice has an invalid schema")
			}
			sp, spOK := notice["sourcePath"].(string)
			dp, dpOK := notice["distributionPath"].(string)
			digest, digestOK := notice["sha256"].(string)
			if !spOK || !dpOK || !digestOK || !validPolicyPath(sp, "cli/vendor/") || !validPolicyPath(dp, "LICENSES/") || !validSHA256(digest) || noticeDestinations[dp] {
				return nil, reject("shipping policy external module notice is invalid")
			}
			noticeDestinations[dp] = true
		}
		modules = append(modules, map[string]string{"path": path, "version": version, "license": license, "moduleSum": moduleSum, "goModSum": goModSum})
	}
	return modules, nil
}

// openBoundedPath walks the destination's parent directories with O_NOFOLLOW.
// The final open also carries O_NOFOLLOW, so a path cannot be redirected by a
// symlink introduced between validation and use.
func openBoundedPath(path string, flags int, mode uint32) (*os.File, error) {
	path = canonicalDarwinPath(path)
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	clean := filepath.Clean(abs)
	volume := filepath.VolumeName(clean)
	rest := strings.TrimPrefix(clean, volume)
	root := string(filepath.Separator)
	if volume != "" {
		root = volume + string(filepath.Separator)
	}
	parts := strings.Split(strings.Trim(rest, string(filepath.Separator)), string(filepath.Separator))
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = unix.Close(fd) }()
	if len(parts) == 0 {
		return nil, errors.New("destination is a directory")
	}
	for _, part := range parts[:len(parts)-1] {
		if part == "" || part == "." || part == ".." {
			return nil, errors.New("unsafe destination")
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		unix.Close(fd)
		fd = next
	}
	name := parts[len(parts)-1]
	if name == "" || name == "." || name == ".." {
		return nil, errors.New("unsafe destination")
	}
	fileFD, err := unix.Openat(fd, name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC, mode)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fileFD), clean), nil
}

func exclusiveCreate(path string, mode uint32) (*os.File, error) {
	return openBoundedPath(path, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, mode)
}

func openBoundedRead(path string) (*os.File, error) {
	return openBoundedPath(path, unix.O_RDONLY, 0)
}

func canonicalDarwinPath(path string) string {
	if runtime.GOOS != "darwin" {
		return path
	}
	for _, alias := range [][2]string{{"/tmp", "/private/tmp"}, {"/var", "/private/var"}} {
		if path == alias[0] {
			return alias[1]
		}
		if strings.HasPrefix(path, alias[0]+"/") {
			return alias[1] + strings.TrimPrefix(path, alias[0])
		}
	}
	return path
}

func WriteMetadata(o MetadataOptions) error {
	if o.Output == "" || o.Version == "" || o.Revision == "" || o.SourceTreeDigest == "" || o.ManifestDigest == "" || o.Target == "" || o.GoVersion == "" {
		return reject("release metadata fields are required")
	}
	validRevision := len(o.Revision) == 40 && strings.IndexFunc(o.Revision, func(r rune) bool {
		return !strings.ContainsRune("0123456789abcdef", r)
	}) < 0
	validDigests := strings.HasPrefix(o.SourceTreeDigest, "sha256:") && strings.HasPrefix(o.ManifestDigest, "sha256:") &&
		validSHA256(strings.TrimPrefix(o.SourceTreeDigest, "sha256:")) && validSHA256(strings.TrimPrefix(o.ManifestDigest, "sha256:"))
	validTarget := o.Target == "linux-amd64" || o.Target == "linux-arm64"
	if !validDigests || !validRevision || !validTarget || !strings.HasPrefix(o.GoVersion, "go1.") {
		return reject("release metadata identity fields are invalid")
	}
	epoch, e := decimal(o.BuildEpoch)
	if e != nil {
		return e
	}
	level := "v8.0"
	if o.Target == "linux-amd64" {
		level = "v1"
	}
	v := map[string]any{
		"schemaVersion": "prufyx.io/community-release-metadata/v1", "version": o.Version,
		"sourceRevision": o.Revision, "sourceTreeDigest": o.SourceTreeDigest,
		"sourceTreeDigestAlgorithm": "sha256(canonical tar of exact Community source stage)",
		"allowlistDigest":           o.ManifestDigest, "releaseManifestDigest": o.ManifestDigest,
		"releaseManifestAlgorithm": "sha256(canonical JSON source-manifest receipt bytes)",
		"target":                   o.Target, "targetArchitectureLevel": level, "cgoEnabled": false,
		"buildEpoch": epoch, "goVersion": o.GoVersion, "trustRootDigest": "UNPINNED",
		"candidateOnly": true, "compatibilityAuthority": "none",
		"artifactProvenance": "Metadata is not an OIDC attestation; independently verify any separately published attestation against the exact artifact and trusted workflow identity",
	}
	b, _ := canonical(v)
	f, e := exclusiveCreate(o.Output, 0600)
	if e != nil {
		return reject("refusing to overwrite metadata")
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	return f.Close()
}

func VerifyVersion(o VersionOptions) error {
	m, e := readJSON(o.Metadata, "release metadata")
	if e != nil {
		return e
	}
	raw := o.Report
	if o.ReportFile != "" {
		raw, e = safeRead(o.ReportFile, 32<<20)
		if e != nil {
			return reject("cannot read version report")
		}
	}
	r, e := decodeObject(raw, "version report")
	if e != nil {
		return e
	}
	data, _ := r["data"].(map[string]any)
	want := map[string]any{
		"version": m["version"], "releaseState": "release", "sourceRevision": m["sourceRevision"],
		"sourceTreeDigest": m["sourceTreeDigest"], "allowlistDigest": m["allowlistDigest"],
		"buildProfile": m["target"], "goVersion": m["goVersion"], "trustRootDigest": "UNPINNED",
		"candidateOnly": true,
	}
	for k, v := range want {
		if !jsonValueEqual(data[k], v) {
			return reject("version identity mismatch for %s", k)
		}
	}
	result, _ := r["result"].(map[string]any)
	if result["status"] != "OK" {
		return reject("version command did not return OK")
	}
	return nil
}
func VerifyDemo(raw []byte) error {
	if len(raw) == 0 {
		return reject("Prometheus demo report is empty")
	}
	m, e := decodeObject(raw, "Prometheus demo report")
	if e != nil {
		return e
	}
	if m["aggregate"] != "UNKNOWN" || m["status"] != "SYNTHETIC_DEMONSTRATION" {
		return reject("Prometheus demo aggregate is not UNKNOWN")
	}
	for _, pin := range []string{"2.55.1", "3.1.0", "linux/arm64/v8"} {
		if !bytes.Contains(raw, []byte(pin)) {
			return reject("Prometheus demo omitted exact pin %s", pin)
		}
	}
	return nil
}
func VerifyScoped(kind, path string) error {
	m, e := readJSON(path, "scoped report")
	if e != nil {
		return e
	}
	if m["assessment"] != "UNKNOWN" {
		return reject("%s report changed aggregate assessment", kind)
	}
	if kind == "cert-manager" {
		c, _ := m["claim"].(map[string]any)
		if c["status"] != "BLOCKED" {
			return reject("cert-manager report changed scoped status")
		}
	} else if kind == "karmada" {
		c, _ := m["check"].(map[string]any)
		claims, _ := c["claims"].([]any)
		blocked := false
		for _, x := range claims {
			if q, ok := x.(map[string]any); ok && q["status"] == "BLOCKED" {
				blocked = true
			}
		}
		if !blocked || m["runtimeReproduced"] != json.Number("0") || m["networkUsed"] != false {
			return reject("Karmada report changed scoped or evidence status")
		}
	} else {
		return reject("unsupported scoped report kind")
	}
	return nil
}
func WriteSmokeReceiptTo(w io.Writer, o SmokeReceiptOptions) error {
	m, e := readJSON(o.Metadata, "release metadata")
	if e != nil {
		return e
	}
	v := map[string]any{
		"schemaVersion": "prufyx.io/community-archive-smoke/v1", "archiveDigest": o.ArchiveDigest,
		"candidateOnly": true, "certManager": map[string]any{"aggregate": "UNKNOWN", "exitCode": 10, "scopedStatus": "BLOCKED"},
		"karmada":        map[string]any{"aggregate": "UNKNOWN", "atLeastOneScopedBlocked": true, "exitCode": 10, "networkUsed": false, "runtimeReproduced": int64(0)},
		"sourceRevision": m["sourceRevision"], "target": o.Target, "trustRootDigest": "UNPINNED",
		"version": o.Version, "versionCommandStatus": "OK",
	}
	b, _ := canonical(v)
	_, e = w.Write(b)
	return e
}
func WriteSmokeReceipt(o SmokeReceiptOptions) error { return WriteSmokeReceiptTo(os.Stdout, o) }

func VerifyMarker(binary, marker string) error {
	if marker == "" {
		return reject("release marker is required")
	}
	b, e := safeRead(binary, 64<<20)
	if e != nil {
		return reject("cannot read binary")
	}
	if bytes.Count(b, []byte(marker)) != 1 {
		return reject("binary does not contain exactly one canonical release identity marker")
	}
	return nil
}
func VerifyArchive(o ArchiveOptions) error {
	epoch, e := decimal(o.BuildEpoch)
	if e != nil {
		return e
	}
	archiveInfo, e := os.Lstat(o.Archive)
	if e != nil || !archiveInfo.Mode().IsRegular() || archiveInfo.Mode()&os.ModeSymlink != 0 || archiveInfo.Size() > maxArchiveCompressed {
		return reject("binary archive is unavailable or exceeds its compressed bound")
	}
	if st, ok := archiveInfo.Sys().(*syscall.Stat_t); ok && st.Nlink != 1 {
		return reject("binary archive must not be hard-linked")
	}
	f, e := openBoundedRead(o.Archive)
	if e != nil {
		return reject("cannot open binary archive")
	}
	defer f.Close()
	gz, e := gzip.NewReader(f)
	if e != nil {
		return reject("binary archive is not gzip")
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	seen := map[string]bool{}
	memberCount := 0
	var uncompressed int64
	expected := map[string]bool{o.PackageName + "/": true}
	regular := map[string][]byte{}
	for _, name := range []string{"LICENSE", "NOTICE", "THIRD-PARTY.md"} {
		b, err := safeRead(filepath.Join(o.RepositoryRoot, name), 32<<20)
		if err != nil {
			return reject("repository legal input is unavailable")
		}
		p := o.PackageName + "/" + name
		expected[p] = false
		regular[p] = b
	}
	for _, name := range []string{"RELEASE-METADATA.json", "SOURCE-REVISION", "prufyx"} {
		expected[o.PackageName+"/"+name] = false
	}
	guidePath := o.PackageName + "/GETTING-STARTED.md"
	expected[guidePath] = false
	regular[guidePath] = BinaryGettingStartedGuide()
	licenseRoot := filepath.Join(o.RepositoryRoot, "LICENSES")
	if _, err := os.Stat(licenseRoot); err != nil {
		return reject("repository LICENSES input is unavailable")
	}
	walkErr := filepath.Walk(licenseRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(o.RepositoryRoot, path)
		rel = filepath.ToSlash(rel)
		archivePath := o.PackageName + "/" + rel
		if info.IsDir() {
			expected[archivePath+"/"] = true
		} else {
			expected[archivePath] = false
			b, e := safeRead(path, 32<<20)
			if e != nil {
				return e
			}
			regular[archivePath] = b
		}
		return nil
	})
	if walkErr != nil {
		return reject("repository LICENSES input is unavailable")
	}
	for {
		h, e := tr.Next()
		if e == io.EOF {
			break
		}
		if e != nil {
			return reject("cannot read binary archive")
		}
		memberCount++
		if memberCount > maxArchiveMembers || h.Size < 0 || h.Size > maxArchiveUncompressed-uncompressed {
			return reject("binary archive exceeds its member or uncompressed bound")
		}
		uncompressed += h.Size
		if seen[h.Name] {
			return reject("binary archive contains a duplicate member")
		}
		seen[h.Name] = true
		if filepath.IsAbs(h.Name) || strings.Contains(h.Name, "//") || strings.Contains(h.Name, "../") || strings.Contains(h.Name, "/./") {
			return reject("binary archive contains an unsafe member name")
		}
		if _, ok := expected[h.Name]; !ok {
			return reject("binary archive contains an unexpected member")
		}
		if h.PAXRecords != nil || h.Linkname != "" || h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || h.ModTime.Unix() != epoch {
			return reject("binary archive contains non-canonical header metadata")
		}
		prefix := o.PackageName + "/"
		if !strings.HasPrefix(h.Name, prefix) {
			return reject("binary archive member is outside package")
		}
		rel := strings.TrimPrefix(h.Name, prefix)
		isDir := expected[h.Name]
		if isDir {
			if h.Typeflag != tar.TypeDir || h.Mode != 0755 {
				return reject("binary archive directory header differs")
			}
		} else {
			mode := int64(0644)
			if rel == "prufyx" {
				mode = 0755
			}
			if h.Typeflag != tar.TypeReg || h.Mode != mode {
				return reject("binary archive file header differs")
			}
			if want, ok := regular[h.Name]; ok {
				body, e := io.ReadAll(tr)
				if e != nil || !bytes.Equal(body, want) {
					return reject("binary archive legal member differs")
				}
			}
		}
	}
	if len(seen) != len(expected) {
		return reject("binary archive member set differs")
	}
	return nil
}

func WriteSBOM(o SBOMOptions) error {
	epoch, e := decimal(o.BuildEpoch)
	if e != nil {
		return e
	}
	t := time.Unix(epoch, 0).UTC().Format("2006-01-02T15:04:05Z")
	analyzed, e := sbomArtifacts(o)
	if e != nil {
		return e
	}
	cliPackage := map[string]any{
		"SPDXID": "SPDXRef-Package-PrufyxCLI", "name": "prufyx-cli", "versionInfo": o.Version,
		"downloadLocation": "https://github.com/prufyx/prufyx/tree/" + o.Revision,
		"filesAnalyzed":    false, "licenseConcluded": "AGPL-3.0-only", "licenseDeclared": "AGPL-3.0-only",
		"copyrightText": "Copyright 2026 Spas Atanasov",
		"externalRefs":  []any{map[string]any{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/github.com/prufyx/prufyx/cli@" + o.Version}},
	}
	goPackage := map[string]any{
		"SPDXID": "SPDXRef-Package-Go", "name": "Go runtime and standard library", "versionInfo": strings.TrimPrefix(o.GoVersion, "go"),
		"downloadLocation": "https://go.dev/dl/" + o.GoVersion + ".src.tar.gz", "filesAnalyzed": false,
		"licenseConcluded": "NOASSERTION", "licenseDeclared": "BSD-3-Clause", "copyrightText": "Copyright 2009 The Go Authors",
		"checksums":    []any{map[string]any{"algorithm": "SHA256", "checksumValue": "4e39b98e42f946fa05ac8bc5b71877df97dbdb7cbb1a777b541667ad7117fd2e"}},
		"comment":      "The reviewed LICENSES directory carries exact notices for the selected CGO-disabled linux/amd64 and linux/arm64 Go 1.26.8 build closure.",
		"externalRefs": []any{map[string]any{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/std@" + strings.TrimPrefix(o.GoVersion, "go")}},
	}
	v := map[string]any{
		"SPDXID": "SPDXRef-DOCUMENT", "creationInfo": map[string]any{"created": t, "creators": []string{"Tool: prufyx-community-release"}},
		"dataLicense": "CC0-1.0", "documentDescribes": []string{"SPDXRef-Package-PrufyxCLI"},
		"documentNamespace": "https://github.com/prufyx/prufyx/releases/tag/" + o.Version + "/sbom-" + o.Revision,
		"name":              "prufyx-cli-" + o.Version + "-release-components", "packages": []any{cliPackage, goPackage},
		"relationships": []any{
			map[string]any{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-Package-PrufyxCLI"},
			map[string]any{"spdxElementId": "SPDXRef-Package-PrufyxCLI", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-Package-Go"},
		},
		"spdxVersion": "SPDX-2.3",
	}
	if o.Policy != "" {
		policy, err := readJSON(o.Policy, "shipping policy")
		if err != nil {
			return err
		}
		modules, err := policyModules(policy)
		if err != nil {
			return err
		}
		packages, ok := v["packages"].([]any)
		if !ok {
			return reject("SBOM package list is invalid")
		}
		relationships, ok := v["relationships"].([]any)
		if !ok {
			return reject("SBOM relationship list is invalid")
		}
		for i, module := range modules {
			path, version := module["path"], module["version"]
			license := module["license"]
			id := fmt.Sprintf("SPDXRef-Package-GoModule-%02d", i+1)
			packages = append(packages, map[string]any{
				"SPDXID": id, "name": path, "versionInfo": version, "downloadLocation": "NOASSERTION", "filesAnalyzed": false,
				"licenseConcluded": "NOASSERTION", "licenseDeclared": license, "copyrightText": "NOASSERTION",
				"comment":      fmt.Sprintf("Vendored Go module bound by module sum %s and go.mod sum %s.", module["moduleSum"], module["goModSum"]),
				"externalRefs": []any{map[string]any{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:golang/" + path + "@" + version}},
			})
			relationships = append(relationships, map[string]any{"spdxElementId": "SPDXRef-Package-PrufyxCLI", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": id})
		}
		v["packages"] = packages
		v["relationships"] = relationships
	}
	if len(analyzed) > 0 {
		if e := bindArtifacts(v, analyzed); e != nil {
			return e
		}
	}
	b, _ := canonical(v)
	f, e := exclusiveCreate(o.Output, 0600)
	if e != nil {
		return reject("refusing to overwrite SBOM")
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	return f.Close()
}

// sbomArtifacts hashes each declared final release artifact. It rejects any
// name that is not a plain file, any unreadable or non-regular file, and any
// duplicate, so the analyzed inventory always describes exact shipped bytes.
func sbomArtifacts(o SBOMOptions) ([]sbomFile, error) {
	if len(o.Artifacts) == 0 {
		if o.ArtifactDir != "" {
			return nil, reject("SBOM artifact directory requires an artifact list")
		}
		return nil, nil
	}
	if o.ArtifactDir == "" {
		return nil, reject("SBOM artifacts require an artifact directory")
	}
	if len(o.Artifacts) > 256 {
		return nil, reject("SBOM artifact list exceeds its bound")
	}
	names := append([]string(nil), o.Artifacts...)
	sort.Strings(names)
	out := make([]sbomFile, 0, len(names))
	previous := ""
	for _, name := range names {
		if name == "" || name != filepath.Base(name) || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00\r\n") {
			return nil, reject("SBOM artifact name is invalid")
		}
		if name == previous {
			return nil, reject("SBOM artifact list contains a duplicate")
		}
		previous = name
		raw, err := safeRead(filepath.Join(o.ArtifactDir, name), maxArchiveCompressed)
		if err != nil {
			return nil, reject("SBOM artifact is unavailable")
		}
		sum256 := sha256.Sum256(raw)
		sum1 := sha1.Sum(raw)
		out = append(out, sbomFile{name: name, sha256: hex.EncodeToString(sum256[:]), sha1: hex.EncodeToString(sum1[:])})
	}
	return out, nil
}

// bindArtifacts adds the analyzed file inventory to the document and switches
// the described package to filesAnalyzed with an SPDX 2.3 package
// verification code, which is the SHA-1 of the concatenated, sorted per-file
// SHA-1 values.
func bindArtifacts(document map[string]any, analyzed []sbomFile) error {
	packages, ok := document["packages"].([]any)
	if !ok || len(packages) == 0 {
		return reject("SBOM package list is invalid")
	}
	described, ok := packages[0].(map[string]any)
	if !ok || described["SPDXID"] != "SPDXRef-Package-PrufyxCLI" {
		return reject("SBOM described package is invalid")
	}
	relationships, ok := document["relationships"].([]any)
	if !ok {
		return reject("SBOM relationship list is invalid")
	}
	files := make([]any, 0, len(analyzed))
	identifiers := make([]string, 0, len(analyzed))
	checksums := make([]string, 0, len(analyzed))
	for i, artifact := range analyzed {
		id := fmt.Sprintf("SPDXRef-File-ReleaseArtifact-%02d", i+1)
		identifiers = append(identifiers, id)
		checksums = append(checksums, artifact.sha1)
		files = append(files, map[string]any{
			"SPDXID": id, "fileName": "./" + artifact.name,
			"checksums": []any{
				map[string]any{"algorithm": "SHA1", "checksumValue": artifact.sha1},
				map[string]any{"algorithm": "SHA256", "checksumValue": artifact.sha256},
			},
			"licenseConcluded": "AGPL-3.0-only", "copyrightText": "Copyright 2026 Spas Atanasov",
			"comment": "Exact published Community release artifact bytes.",
		})
		relationships = append(relationships, map[string]any{
			"spdxElementId": "SPDXRef-Package-PrufyxCLI", "relationshipType": "CONTAINS", "relatedSpdxElement": id,
		})
	}
	sort.Strings(checksums)
	code := sha1.Sum([]byte(strings.Join(checksums, "")))
	described["filesAnalyzed"] = true
	described["hasFiles"] = identifiers
	described["packageVerificationCode"] = map[string]any{"packageVerificationCodeValue": hex.EncodeToString(code[:])}
	document["files"] = files
	document["relationships"] = relationships
	return nil
}

func jsonValueEqual(a, b any) bool {
	if na, ok := a.(json.Number); ok {
		if nb, ok := b.(json.Number); ok {
			return na.String() == nb.String()
		}
	}
	return fmt.Sprintf("%T:%v", a, a) == fmt.Sprintf("%T:%v", b, b)
}

// Run dispatches a release helper. stdin and stdout are supplied by the
// caller so tests and embedding code never inherit process-global streams.
func Run(args []string, stdin io.Reader, stdout, _ io.Writer) error {
	if len(args) == 0 {
		return reject("missing release helper command")
	}
	switch args[0] {
	case "release-metadata":
		f, e := parseFlags(args[1:], map[string]bool{
			"output":             true,
			"version":            true,
			"revision":           true,
			"source-tree-digest": true,
			"manifest-digest":    true,
			"target":             true,
			"build-epoch":        true,
			"go-version":         true,
		})
		if e != nil {
			return e
		}
		return WriteMetadata(MetadataOptions{
			Output:           f["output"],
			Version:          f["version"],
			Revision:         f["revision"],
			SourceTreeDigest: f["source-tree-digest"],
			ManifestDigest:   f["manifest-digest"],
			Target:           f["target"],
			BuildEpoch:       f["build-epoch"],
			GoVersion:        f["go-version"],
		})
	case "release-verify-version":
		f, e := parseFlagsOptional(args[1:], map[string]bool{
			"metadata":     true,
			"report-file":  true,
			"report-stdin": false,
		}, map[string]bool{"metadata": true})
		if e != nil {
			return e
		}
		var b []byte
		if f["report-stdin"] == "true" {
			b, e = io.ReadAll(stdin)
			if e != nil {
				return reject("cannot read version report")
			}
		}
		return VerifyVersion(VersionOptions{
			Metadata:   f["metadata"],
			ReportFile: f["report-file"],
			Report:     b,
		})
	case "release-verify-demo":
		b, e := io.ReadAll(stdin)
		if e != nil {
			return reject("cannot read demo report")
		}
		return VerifyDemo(b)
	case "release-verify-scoped":
		f, e := parseFlags(args[1:], map[string]bool{"kind": true, "report": true})
		if e != nil {
			return e
		}
		return VerifyScoped(f["kind"], f["report"])
	case "release-archive-smoke-receipt":
		f, e := parseFlags(args[1:], map[string]bool{"version": true, "target": true, "archive-digest": true, "metadata": true})
		if e != nil {
			return e
		}
		return WriteSmokeReceiptTo(stdout, SmokeReceiptOptions{
			Version:       f["version"],
			Target:        f["target"],
			ArchiveDigest: f["archive-digest"],
			Metadata:      f["metadata"],
		})
	case "release-verify-archive":
		f, e := parseFlags(args[1:], map[string]bool{"archive": true, "package-name": true, "repository-root": true, "build-epoch": true})
		if e != nil {
			return e
		}
		return VerifyArchive(ArchiveOptions{Archive: f["archive"], PackageName: f["package-name"], RepositoryRoot: f["repository-root"], BuildEpoch: f["build-epoch"]})
	case "release-verify-marker":
		f, e := parseFlags(args[1:], map[string]bool{"binary": true, "marker": true})
		if e != nil {
			return e
		}
		return VerifyMarker(f["binary"], f["marker"])
	case "release-sbom":
		allowed := map[string]bool{"output": true, "version": true, "revision": true, "build-epoch": true, "go-version": true, "policy": true, "artifact-dir": true, "artifacts": true}
		required := map[string]bool{"output": true, "version": true, "revision": true, "build-epoch": true, "go-version": true, "policy": true}
		f, e := parseFlagsOptional(args[1:], allowed, required)
		if e != nil {
			return e
		}
		var artifacts []string
		if f["artifacts"] != "" {
			artifacts = strings.Split(f["artifacts"], ",")
		}
		return WriteSBOM(SBOMOptions{Output: f["output"], Version: f["version"], Revision: f["revision"], BuildEpoch: f["build-epoch"], GoVersion: f["go-version"], Policy: f["policy"], ArtifactDir: f["artifact-dir"], Artifacts: artifacts})
	default:
		return reject("unknown release helper command")
	}
}
func parseFlags(args []string, allowed map[string]bool) (map[string]string, error) {
	return parseFlagsOptional(args, allowed, allowed)
}
func parseFlagsOptional(args []string, allowed, required map[string]bool) (map[string]string, error) {
	out := map[string]string{}
	seen := map[string]bool{}
	for i := 0; i < len(args); i++ {
		if !strings.HasPrefix(args[i], "--") {
			return nil, reject("invalid release helper arguments")
		}
		name := strings.TrimPrefix(args[i], "--")
		takes, ok := allowed[name]
		if !ok || seen[name] {
			return nil, reject("invalid release helper arguments")
		}
		if takes {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return nil, reject("invalid release helper arguments")
			}
			out[name] = args[i+1]
			i++
		} else {
			out[name] = "true"
		}
		seen[name] = true
	}
	for name := range required {
		if !seen[name] || out[name] == "" {
			return nil, reject("invalid release helper arguments")
		}
	}
	return out, nil
}
