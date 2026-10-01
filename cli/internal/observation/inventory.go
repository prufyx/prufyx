// SPDX-License-Identifier: AGPL-3.0-only

package observation

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
)

// InventoryLimits bounds descriptor-relative observation discovery. Names are
// charged independently so untrusted directory entries cannot grow an
// in-memory tree before file/content limits are enforced.
type InventoryLimits struct {
	MaxTotalBytes  int64
	MaxFileBytes   int64
	MaxFiles       int
	MaxDirectories int
	MaxDepth       int
	MaxNameBytes   int64
}

const defaultInventoryNameBytes = 4 << 20

func normalizeInventoryLimits(l InventoryLimits) (InventoryLimits, error) {
	if l.MaxTotalBytes == 0 {
		l.MaxTotalBytes = maxInputBytes
	}
	if l.MaxFileBytes == 0 {
		l.MaxFileBytes = maxFileBytes
	}
	if l.MaxFiles == 0 {
		l.MaxFiles = maxFiles
	}
	if l.MaxDirectories == 0 {
		l.MaxDirectories = maxDirectories
	}
	if l.MaxDepth == 0 {
		l.MaxDepth = maxPathDepth
	}
	if l.MaxNameBytes == 0 {
		l.MaxNameBytes = defaultInventoryNameBytes
	}
	if l.MaxFileBytes == maxFileBytes && l.MaxTotalBytes < l.MaxFileBytes {
		// An omitted per-file limit inherits the caller's smaller total budget;
		// explicit per-file limits remain subject to the total bound below.
		l.MaxFileBytes = l.MaxTotalBytes
	}
	if l.MaxTotalBytes < 1 || l.MaxTotalBytes > maxInputBytes || l.MaxFileBytes < 1 || l.MaxFileBytes > maxFileBytes || l.MaxFileBytes > l.MaxTotalBytes || l.MaxFiles < 1 || l.MaxFiles > 16384 || l.MaxDirectories < 1 || l.MaxDirectories > 4096 || l.MaxDepth < 1 || l.MaxDepth > maxPathDepth || l.MaxNameBytes < 1 || l.MaxNameBytes > defaultInventoryNameBytes {
		return l, fmt.Errorf("invalid inventory limits: %w", ErrInvalid)
	}
	return l, nil
}

type inventoryState struct {
	limits                  InventoryLimits
	files, directories      int
	nameBytes, contentBytes int64
	leaves                  []*Root
	ctx                     context.Context
}

// inventoryAdmissionTransitionHook exists only to make the stat-to-open
// replacement boundary deterministic in tests. Production leaves it nil; it
// must never be used to extend the observation capability or read a second
// pathname.
var inventoryAdmissionTransitionHook func(parent *os.File, name string)

func (s *inventoryState) closeLeaves() {
	for _, leaf := range s.leaves {
		_ = leaf.Close()
	}
	s.leaves = nil
}
func (s *inventoryState) addName(name string) error {
	if int64(len(name)) > s.limits.MaxNameBytes-s.nameBytes {
		return fmt.Errorf("inventory names exceed %d bytes: %w", s.limits.MaxNameBytes, ErrInvalid)
	}
	s.nameBytes += int64(len(name))
	return nil
}
func (s *inventoryState) addFile(size int64) error {
	if s.files >= s.limits.MaxFiles {
		return fmt.Errorf("inventory files exceed %d: %w", s.limits.MaxFiles, ErrInvalid)
	}
	if size < 0 || size > s.limits.MaxFileBytes || size > s.limits.MaxTotalBytes-s.contentBytes {
		return fmt.Errorf("inventory content exceeds %d bytes: %w", s.limits.MaxTotalBytes, ErrInvalid)
	}
	s.files++
	s.contentBytes += size
	return nil
}

func inventoryObservationDir(s *inventoryState, dir *os.File, depth int, segments []string, retain bool, bound stableIdentity) error {
	if err := checkContext(s.ctx); err != nil {
		return err
	}
	if depth > s.limits.MaxDepth {
		return fmt.Errorf("inventory depth exceeds %d: %w", s.limits.MaxDepth, ErrInvalid)
	}
	if s.directories >= s.limits.MaxDirectories {
		return fmt.Errorf("inventory directories exceed %d: %w", s.limits.MaxDirectories, ErrInvalid)
	}
	s.directories++
	hasIndex := false
	var bindings map[string]fileBinding
	if retain {
		// Keep a bounded, per-leaf identity index. This is deliberately sized
		// after the file budget has been checked, so a wide directory cannot
		// force an unbounded allocation before admission fails.
		bindings = make(map[string]fileBinding)
	}
	for {
		if err := checkContext(s.ctx); err != nil {
			return err
		}
		// n=1 prevents os.ReadDir's whole-directory materialization and sorting.
		entries, err := dir.ReadDir(1)
		if err != nil && err != io.EOF {
			return fmt.Errorf("inventory directory read: %w", err)
		}
		if len(entries) == 0 {
			break
		}
		name := entries[0].Name()
		if err := s.addName(name); err != nil {
			return err
		}
		identity, err := observationStatAt(dir, name)
		if err != nil {
			return fmt.Errorf("inventory entry stat: %w", ErrInvalid)
		}
		if identity.rawMode&0170000 == 0120000 {
			return fmt.Errorf("inventory symlink: %w", ErrInvalid)
		}
		switch {
		case identity.isDirectory():
			if depth == s.limits.MaxDepth {
				return fmt.Errorf("inventory depth exceeds %d: %w", s.limits.MaxDepth, ErrInvalid)
			}
			child, childIdentity, err := observationOpenBoundDirectory(dir, name)
			if err != nil {
				return capabilityError("open inventory directory", err)
			}
			childSegments := append(append([]string(nil), segments...), name)
			childRetain := len(childSegments) == 3 && childSegments[0] == "observations" && len(childSegments[1]) > 1 && len(childSegments[2]) == 6
			if err := inventoryObservationDir(s, child, depth+1, childSegments, childRetain, childIdentity); err != nil {
				_ = child.Close()
				return err
			}
			if !childRetain {
				_ = child.Close()
			}
		case identity.isRegular():
			if identity.links != 1 {
				return fmt.Errorf("inventory hard-linked file: %w", ErrInvalid)
			}
			// Admit the stat-sized file before opening or hashing it.  The size is
			// untrusted metadata, but it is the only bounded admission decision
			// available before reading bytes.  A file larger than the remaining
			// budget must therefore cause zero content I/O, including for sparse
			// files.  Any later identity/read failure aborts the whole inventory,
			// so the reservation needs no rollback.
			if err := s.addFile(identity.size); err != nil {
				return err
			}
			if inventoryAdmissionTransitionHook != nil {
				inventoryAdmissionTransitionHook(dir, name)
			}
			// Bind every regular entry once, relative to this retained
			// directory. This closes the stat/open replacement window before
			// its size is admitted to the bounded inventory.
			boundFile, boundIdentity, err := observationOpenBoundFile(dir, name)
			if err != nil {
				return capabilityError("open inventory file", err)
			}
			// The pre-open stat is the admission identity. A later pathname
			// replacement may be internally stable yet still be a different,
			// larger file. Never let that replacement supply the digest size or
			// bypass either budget.
			if !boundIdentity.equal(identity) {
				_ = boundFile.Close()
				return fmt.Errorf("inventory file identity differs from admission: %w", ErrIntegrity)
			}
			remainingForAdmitted := s.limits.MaxTotalBytes - (s.contentBytes - identity.size)
			if boundIdentity.size < 0 || boundIdentity.size > s.limits.MaxFileBytes || boundIdentity.size > remainingForAdmitted {
				_ = boundFile.Close()
				return fmt.Errorf("inventory opened file exceeds admitted budget: %w", ErrInvalid)
			}
			digest, digestErr := observationDigestFile(s.ctx, boundFile, identity.size)
			closeErr := boundFile.Close()
			if digestErr != nil {
				return fmt.Errorf("inventory file digest: %w", digestErr)
			}
			if closeErr != nil {
				return fmt.Errorf("close inventory file: %w", ErrIntegrity)
			}
			if retain {
				bindings[name] = fileBinding{identity: boundIdentity, digest: digest}
			}
			if name == "index.json" && retain {
				hasIndex = true
			}
		default:
			return fmt.Errorf("inventory non-regular entry: %w", ErrInvalid)
		}
	}
	if retain {
		if hasIndex {
			s.leaves = append(s.leaves, &Root{file: dir, identity: bound, bindings: bindings})
			return nil
		}
		_ = dir.Close()
	}
	return nil
}

// ReadFile reads a bounded regular single-link file relative to a retained
// Root. It never reopens a caller-controlled pathname.
func (r *Root) ReadFile(ctx context.Context, name string, maxBytes int64) ([]byte, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	if err := validateLeaf(name); err != nil {
		return nil, err
	}
	if maxBytes < 0 || maxBytes > maxInputBytes {
		return nil, fmt.Errorf("invalid descriptor read limit: %w", ErrInvalid)
	}
	dir, err := r.ownedSnapshot()
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	r.mu.Lock()
	binding, ok := r.bindings[name]
	r.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("file was not admitted during inventory: %w", ErrInvalid)
	}
	file, before, err := observationOpenBoundFile(dir, name)
	if err != nil {
		return nil, capabilityError("open descriptor file", err)
	}
	defer file.Close()
	if !before.equal(binding.identity) {
		return nil, fmt.Errorf("descriptor file identity differs from inventory: %w", ErrIntegrity)
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read descriptor file: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("descriptor file exceeds %d bytes: %w", maxBytes, ErrInvalid)
	}
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	after, err := observationStableIdentity(file)
	if err != nil || !before.equal(after) {
		return nil, fmt.Errorf("descriptor file changed while reading: %w", ErrIntegrity)
	}
	if got := sha256.Sum256(data); got != binding.digest {
		return nil, fmt.Errorf("descriptor file content differs from inventory: %w", ErrIntegrity)
	}
	return data, nil
}

// InventoryObservation discovers fixed observation leaves through descriptor-
// relative operations. Returned Roots are owned by the caller.
func (r *Root) InventoryObservation(ctx context.Context, limits InventoryLimits) ([]*Root, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}
	normalized, err := normalizeInventoryLimits(limits)
	if err != nil {
		return nil, err
	}
	dir, err := r.ownedSnapshot()
	if err != nil {
		return nil, err
	}
	defer dir.Close()
	state := &inventoryState{limits: normalized, ctx: ctx}
	if err := inventoryObservationDir(state, dir, 0, nil, false, stableIdentity{}); err != nil {
		state.closeLeaves()
		return nil, err
	}
	return state.leaves, nil
}
