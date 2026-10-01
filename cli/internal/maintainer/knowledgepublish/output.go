// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepublish

import (
	"fmt"
	"os"
	"path/filepath"
)

const maxOutputBytes = 4 << 20

// WritePreparation creates one new private directory containing the three
// exact public signing artifacts. A failed write leaves that new directory in
// place for explicit operator inspection or cleanup.
func WritePreparation(path string, prepared Preparation) error {
	if !validAbsoluteOutput(path) || prepared.Role == "" || len(prepared.UnsignedMetadata) == 0 || len(prepared.Payload) == 0 || len(prepared.Request) == 0 {
		return ErrRejected
	}
	parent, err := openPrivateRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	name := filepath.Base(path)
	if err := parent.Mkdir(name, 0o700); err != nil {
		return fmt.Errorf("create signing output: %w", ErrRejected)
	}
	directory, err := parent.OpenRoot(name)
	if err != nil {
		return fmt.Errorf("open signing output: %w", ErrRejected)
	}
	defer directory.Close()
	if err := chmodRoot(directory, 0o700); err != nil {
		return fmt.Errorf("secure signing output: %w", ErrRejected)
	}
	for _, artifact := range []struct {
		name string
		raw  []byte
	}{
		{prepared.Role + ".unsigned.json", prepared.UnsignedMetadata},
		{prepared.Role + ".payload.json", prepared.Payload},
		{prepared.Role + ".request.json", prepared.Request},
	} {
		if err := writeExclusiveAt(directory, artifact.name, artifact.raw); err != nil {
			return err
		}
	}
	if err := syncRoot(directory); err != nil {
		return fmt.Errorf("sync signing output: %w", ErrRejected)
	}
	if err := syncRoot(parent); err != nil {
		return fmt.Errorf("sync signing parent: %w", ErrRejected)
	}
	return nil
}

// WriteExclusive publishes one complete public artifact without overwrite. A
// failed write leaves the newly created path in place for explicit inspection.
func WriteExclusive(path string, raw []byte) error {
	if !validAbsoluteOutput(path) || len(raw) == 0 || len(raw) > maxOutputBytes {
		return ErrRejected
	}
	parent, err := openPrivateRoot(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer parent.Close()
	if err := writeExclusiveAt(parent, filepath.Base(path), raw); err != nil {
		return err
	}
	if err := syncRoot(parent); err != nil {
		return fmt.Errorf("sync output parent: %w", ErrRejected)
	}
	return nil
}

func writeExclusiveAt(parent *os.Root, name string, raw []byte) (err error) {
	return writeExclusiveAtWith(parent, name, raw, writeAndSync)
}

func writeExclusiveAtWith(parent *os.Root, name string, raw []byte, finish func(*os.File, []byte) error) (err error) {
	if parent == nil || name == "" || name == "." || filepath.Base(name) != name || len(raw) == 0 || len(raw) > maxOutputBytes || finish == nil {
		return ErrRejected
	}
	file, err := parent.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create exclusive output: %w", ErrRejected)
	}
	closed := false
	defer func() {
		if !closed {
			_ = file.Close()
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("secure exclusive output: %w", ErrRejected)
	}
	if err := finish(file, raw); err != nil {
		return fmt.Errorf("finish exclusive output: %w", ErrRejected)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close exclusive output: %w", ErrRejected)
	}
	closed = true
	return nil
}

func writeAndSync(file *os.File, raw []byte) error {
	if _, err := file.Write(raw); err != nil {
		return err
	}
	return file.Sync()
}

func openPrivateRoot(path string) (*os.Root, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrRejected
	}
	before, err := os.Lstat(path)
	if err != nil || !before.IsDir() || before.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("output parent must be a real directory: %w", ErrRejected)
	}
	root, err := os.OpenRoot(path)
	if err != nil {
		return nil, fmt.Errorf("open output parent: %w", ErrRejected)
	}
	actual, err := root.Stat(".")
	if err != nil || !os.SameFile(before, actual) || actual.Mode().Perm() != 0o700 {
		_ = root.Close()
		return nil, fmt.Errorf("output parent must be an unchanged 0700 directory: %w", ErrRejected)
	}
	if uid, ok := fileUID(actual); ok && uid != os.Getuid() {
		_ = root.Close()
		return nil, fmt.Errorf("output parent owner mismatch: %w", ErrRejected)
	}
	return root, nil
}

func syncRoot(root *os.Root) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}

func chmodRoot(root *os.Root, mode os.FileMode) error {
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	if err := directory.Chmod(mode); err != nil {
		_ = directory.Close()
		return err
	}
	info, err := directory.Stat()
	if err != nil || info.Mode().Perm() != mode {
		_ = directory.Close()
		return ErrRejected
	}
	return directory.Close()
}

func validAbsoluteOutput(path string) bool {
	return filepath.IsAbs(path) && filepath.Clean(path) == path && filepath.Base(path) != "." && filepath.Base(path) != string(filepath.Separator)
}
