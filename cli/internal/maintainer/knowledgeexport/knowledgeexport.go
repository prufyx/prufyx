// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgeexport writes a bounded unsigned public CNCF source target.
// It has no access to local knowledge stores, trust roots, or signing keys.
package knowledgeexport

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

var ErrRejected = errors.New("knowledge export rejected")

type Options struct {
	Profile  string
	Revision string
	Output   string
}

// Write exports the complete embedded public CNCF source-rule target to one
// new regular file. It is deliberately not a store export or package signer.
func Write(options Options) error {
	if options.Profile != "cncf" || options.Output == "" {
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
