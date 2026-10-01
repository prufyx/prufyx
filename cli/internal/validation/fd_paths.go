// SPDX-License-Identifier: AGPL-3.0-only

package validation

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
)

func publishNoReplaceDirectory(parent, stageDirectory *os.File, parentPath, stageName, finalName string, expected map[string]RunArtifact, files []string) error {
	return publishDescriptorBoundDirectory(parent, stageDirectory, parentPath, stageName, finalName, expected, files)
}

func publishLegacyNoReplaceDirectory(parent, stageDirectory *os.File, parentPath, stageName, finalName string, expected map[string]RunArtifact, files []string) error {
	return publishDescriptorBoundDirectory(parent, stageDirectory, parentPath, stageName, finalName, expected, files)
}

// openInputFile walks every absolute parent component through retained
// directory descriptors, then opens the leaf with no-follow/non-blocking
// flags. This prevents ancestor symlink traversal and FIFO/device blocking.
func openInputFile(path string) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	abs = normalizeSystemAlias(abs)
	parent, err := openDirectoryPath(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	file, err := openRelativeFile(parent, filepath.Base(abs), 0, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, fmt.Errorf("input is not a regular file")
	}
	return file, nil
}

func singleLink(info os.FileInfo) bool {
	if info == nil {
		return false
	}
	v := reflect.ValueOf(info.Sys())
	if v.IsValid() && v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return false
	}
	field := v.FieldByName("Nlink")
	if !field.IsValid() {
		return false
	}
	switch field.Kind() {
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return field.Uint() == 1
	default:
		return false
	}
}

// openDirectoryPath resolves an existing absolute path one component at a
// time. Missing parents are rejected; callers create only the final output
// directory with mkdirRelative after this walk has retained its parent FD.
func openDirectoryPath(path string) (*os.File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	abs = normalizeSystemAlias(abs)
	if !filepath.IsAbs(abs) {
		return nil, fmt.Errorf("directory path is not absolute")
	}
	current, err := openRootDirectory()
	if err != nil {
		return nil, err
	}
	components := strings.Split(strings.TrimPrefix(filepath.Clean(abs), string(filepath.Separator)), string(filepath.Separator))
	for _, component := range components {
		if component == "" || component == "." {
			continue
		}
		next, err := openRelativeDirectory(current, component)
		if err != nil {
			_ = current.Close()
			return nil, err
		}
		_ = current.Close()
		current = next
	}
	return current, nil
}

func normalizeSystemAlias(path string) string {
	if runtime.GOOS != "darwin" {
		return path
	}
	for _, pair := range [][2]string{{"/tmp", "/private/tmp"}, {"/var", "/private/var"}} {
		logical, resolved := pair[0], pair[1]
		if path == logical {
			return resolved
		}
		prefix := logical + string(filepath.Separator)
		if strings.HasPrefix(path, prefix) {
			return resolved + strings.TrimPrefix(path, logical)
		}
	}
	return path
}
