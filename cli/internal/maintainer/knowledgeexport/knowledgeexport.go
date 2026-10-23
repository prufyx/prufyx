// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgeexport writes a bounded unsigned public CNCF source target.
// It has no access to local knowledge stores, trust roots, or signing keys.
package knowledgeexport

import (
	"errors"
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

// Write exports the complete embedded public CNCF source-rule target to one
// new regular file, or, for the cncf-projects profile, the per-project
// targets to one new directory. It is deliberately not a store export or
// package signer.
func Write(options Options) error {
	if options.Profile == ProfileCNCFProjects {
		return writeProjects(options)
	}
	if options.Profile != "cncf" || options.Output == "" || options.PreviousIndex != "" {
		return ErrRejected
	}
	raw, err := cncfcheck.ExportEmbeddedExternalBundle(options.Revision)
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
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return ErrRejected
	}
	defer parent.Close()
	name := filepath.Base(abs)
	f, err := parent.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return ErrRejected
	}
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		_ = f.Close()
		return ErrRejected
	}
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()
	if err := f.Chmod(0o644); err != nil {
		return ErrRejected
	}
	if _, err := f.Write(raw); err != nil {
		return ErrRejected
	}
	if err := f.Sync(); err != nil {
		return ErrRejected
	}
	if err := f.Close(); err != nil {
		return ErrRejected
	}
	closed = true
	dir, err := parent.Open(".")
	if err != nil {
		return ErrRejected
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return ErrRejected
	}
	if err := dir.Close(); err != nil {
		return ErrRejected
	}
	return nil
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
