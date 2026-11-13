// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgeexport writes a bounded unsigned public CNCF source target.
// It has no access to local knowledge stores, trust roots, or signing keys.
package knowledgeexport

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

var ErrRejected = errors.New("knowledge export rejected")

type Options struct {
	Profile  string
	Revision string
	Output   string
	// PreviousIndex is the optional path of the previously published
	// index; only the cncf-projects profile reads it. Projects whose target
	// bytes are unchanged keep their previous revision.
	PreviousIndex string
}

// ProfileCNCFProjects exports the per-project layout: Output is a new
// directory that receives knowledge/cncf/index.v1.json and one target per
// project, the layout "knowledge-publish" signs with --targets-dir.
const ProfileCNCFProjects = "cncf-projects"

// Write exports the per-project targets to a new directory. The retired
// single-target profile is rejected rather than reinterpreted.
func Write(options Options) error {
	if options.Profile == "" {
		options.Profile = ProfileCNCFProjects
	}
	if options.Profile != ProfileCNCFProjects {
		return fmt.Errorf("use cncf-projects: %w", ErrRejected)
	}
	return writeProjects(options)
}

func writeProjects(options Options) error {
	if options.Output == "" {
		return ErrRejected
	}
	var index cncfcheck.ExternalTarget
	var projects []cncfcheck.ExternalTarget
	var err error
	if options.PreviousIndex == "" {
		index, projects, err = cncfcheck.BuildEmbeddedExternalTargets(options.Revision, nil)
	} else {
		var previous []byte
		if previous, err = readBounded(options.PreviousIndex); err != nil {
			return ErrRejected
		}
		index, projects, err = cncfcheck.BuildEmbeddedExternalTargetsFrom(options.Revision, previous)
	}
	if err != nil {
		return ErrRejected
	}
	abs, err := filepath.Abs(options.Output)
	if err != nil || filepath.Base(abs) == "." || filepath.Base(abs) == string(filepath.Separator) {
		return ErrRejected
	}
	parentPath, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return ErrRejected
	}
	dir := filepath.Join(parentPath, filepath.Base(abs))
	if err := os.Mkdir(dir, 0o755); err != nil {
		return ErrRejected
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return ErrRejected
	}
	defer root.Close()
	for _, target := range append([]cncfcheck.ExternalTarget{index}, projects...) {
		if err := writeTarget(root, target); err != nil {
			return ErrRejected
		}
	}
	return nil
}

func writeTarget(root *os.Root, target cncfcheck.ExternalTarget) error {
	if err := root.MkdirAll(path.Dir(target.Path), 0o755); err != nil {
		return err
	}
	f, err := root.OpenFile(filepath.FromSlash(target.Path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := f.Write(target.Bytes); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func readBounded(name string) ([]byte, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, ErrRejected
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(cncfcheck.MaxExternalTargetBytes)+1))
	if err != nil || len(raw) > cncfcheck.MaxExternalTargetBytes {
		return nil, ErrRejected
	}
	return raw, nil
}
