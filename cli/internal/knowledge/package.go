// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"archive/tar"
	"bytes"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/theupdateframework/go-tuf/v2/metadata"
)

const (
	maxPackageBytes = 4 << 20
	maxPackageFiles = 16
	maxPackageEntry = 1 << 20
	maxPackageTotal = 2 << 20
)

var packageNameRE = regexp.MustCompile(`^(?:metadata/[1-9][0-9]{0,9}\.(?:root|snapshot|targets)\.json|metadata/timestamp\.json|targets/knowledge/[0-9a-f]{64}\.cert-manager\.v1\.json)$`)
var metadataNameRE = regexp.MustCompile(`^metadata/(?:[1-9][0-9]{0,9}\.(?:root|snapshot|targets)\.json|timestamp\.json)$`)

type importPackage struct {
	files      map[string][]byte
	digest     string
	targetPath string
}

func readImportPackage(filePath string) (importPackage, error) {
	return readImportPackageForProfile(filePath, certManagerProfile())
}

func readImportPackageForProfile(filePath string, profile profileSpec) (importPackage, error) {
	if !profile.valid() {
		return importPackage{}, ErrIntegrity
	}
	limitBytes, limitFiles, limitTotal := profile.packageLimits()
	raw, info, err := currentbundle.ReadBoundedFileInfo(filePath, limitBytes)
	if err != nil || info == nil || !info.Mode().IsRegular() {
		return importPackage{}, fmt.Errorf("open package: %w", ErrInvalid)
	}
	if err := packageLayoutMismatch(raw, profile); err != nil {
		return importPackage{}, err
	}
	reader := tar.NewReader(bytes.NewReader(raw))
	files := map[string][]byte{}
	var ordered []string
	total := int64(0)
	for {
		header, err := reader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return importPackage{}, fmt.Errorf("read package: %w", ErrInvalid)
		}
		//lint:ignore SA1019 Xattrs is deprecated for writing, but this parser must reject legacy extended attributes.
		legacyXattrs := header.Xattrs != nil
		if len(files) >= limitFiles || header.Typeflag != tar.TypeReg || header.Size < 1 || header.Size > maxPackageEntry || header.Mode != 0o644 || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" || header.Linkname != "" || !header.ModTime.Equal(time.Unix(0, 0)) || !header.AccessTime.IsZero() || !header.ChangeTime.IsZero() || header.Devmajor != 0 || header.Devminor != 0 || header.PAXRecords != nil || legacyXattrs {
			return importPackage{}, fmt.Errorf("package header: %w", ErrInvalid)
		}
		name := header.Name
		if !utf8.ValidString(name) || path.Clean(name) != name || strings.HasPrefix(name, "/") || !packageMemberName(name, profile.targetPath) {
			return importPackage{}, fmt.Errorf("package path: %w", ErrInvalid)
		}
		if _, exists := files[name]; exists {
			return importPackage{}, fmt.Errorf("duplicate package path: %w", ErrInvalid)
		}
		total += header.Size
		if total > limitTotal {
			return importPackage{}, fmt.Errorf("package total size: %w", ErrInvalid)
		}
		data, err := io.ReadAll(io.LimitReader(reader, header.Size+1))
		if err != nil || int64(len(data)) != header.Size {
			return importPackage{}, fmt.Errorf("package entry: %w", ErrInvalid)
		}
		files[name] = data
		if strings.HasPrefix(name, "metadata/") {
			if err := validateTUFJSONForTarget(data, profile.targetPath); err != nil {
				return importPackage{}, fmt.Errorf("metadata JSON %s: %w", name, ErrIntegrity)
			}
		}
		ordered = append(ordered, name)
	}
	if len(files) < 4 {
		return importPackage{}, fmt.Errorf("incomplete package: %w", ErrInvalid)
	}
	if _, ok := files["metadata/timestamp.json"]; !ok {
		return importPackage{}, fmt.Errorf("timestamp missing: %w", ErrInvalid)
	}
	if !sort.StringsAreSorted(ordered) {
		return importPackage{}, fmt.Errorf("package member order: %w", ErrInvalid)
	}
	var canonical bytes.Buffer
	w := tar.NewWriter(&canonical)
	for _, name := range ordered {
		data := files[name]
		format := tar.FormatUSTAR
		if len(path.Base(name)) > 100 {
			format = tar.FormatGNU
		}
		h := &tar.Header{Name: name, Mode: 0o644, Uid: 0, Gid: 0, Size: int64(len(data)), ModTime: time.Unix(0, 0), Typeflag: tar.TypeReg, Format: format}
		if err := w.WriteHeader(h); err != nil {
			return importPackage{}, fmt.Errorf("canonical package: %w", ErrInvalid)
		}
		if _, err := w.Write(data); err != nil {
			return importPackage{}, fmt.Errorf("canonical package: %w", ErrInvalid)
		}
	}
	if err := w.Close(); err != nil || !bytes.Equal(canonical.Bytes(), raw) {
		return importPackage{}, fmt.Errorf("non-canonical or trailing package bytes: %w", ErrInvalid)
	}
	return importPackage{files: files, digest: digestBytes(raw), targetPath: profile.targetPath}, nil
}

func packageMemberName(name, targetPath string) bool {
	if metadataNameRE.MatchString(name) {
		return true
	}
	if targetPath == TargetPath && packageNameRE.MatchString(name) {
		return true
	}
	if isSplitTarget(targetPath) {
		return splitMemberName(name)
	}
	if !strings.HasPrefix(name, "targets/knowledge/") || !strings.HasSuffix(name, "."+path.Base(targetPath)) {
		return false
	}
	prefix := "targets/knowledge/"
	digest := strings.TrimSuffix(strings.TrimPrefix(name, prefix), "."+path.Base(targetPath))
	return len(digest) == 64 && isLowerHex(digest, 64)
}

type memoryFetcher struct {
	files      map[string][]byte
	served     map[string][]byte
	hook       func(string) error
	targetPath string
}

func newMemoryFetcher(pkg importPackage, hook func(string) error) *memoryFetcher {
	return &memoryFetcher{files: pkg.files, served: map[string][]byte{}, hook: hook, targetPath: pkg.targetPath}
}

func (f *memoryFetcher) DownloadFile(urlPath string, maxLength int64, _ time.Duration) ([]byte, error) {
	const base = "https://offline.invalid/"
	if maxLength < 1 || !strings.HasPrefix(urlPath, base) {
		return nil, fmt.Errorf("fetch route: %w", ErrInvalid)
	}
	name := strings.TrimPrefix(urlPath, base)
	if !packageMemberName(name, f.targetPath) {
		return nil, fmt.Errorf("fetch path: %w", ErrInvalid)
	}
	data, ok := f.files[name]
	if !ok {
		if strings.HasPrefix(name, "metadata/") && strings.HasSuffix(name, ".root.json") {
			return nil, &metadata.ErrDownloadHTTP{StatusCode: 404, URL: urlPath}
		}
		return nil, fmt.Errorf("package member %s missing: %w", name, ErrInvalid)
	}
	if int64(len(data)) > maxLength {
		return nil, &metadata.ErrDownloadLengthMismatch{Msg: "offline package member exceeds role bound"}
	}
	if f.hook != nil {
		if err := f.hook(name); err != nil {
			return nil, err
		}
	}
	copy := append([]byte(nil), data...)
	f.served[name] = copy
	return copy, nil
}
