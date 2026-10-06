// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgeauto decides, without reading any clock or network,
// whether a command uses the verified knowledge database that `prufyx db
// update` installs in the default store location, or the knowledge built
// into the binary.
//
// The rule is fail-closed. No default store means embedded knowledge. A
// default store that is present but cannot be used (damaged, unverifiable,
// expired, rolled back, private-mode wrong, or rooted in a different trust
// root than the product pin) is an error: it never falls back silently,
// because that could hide tampering or serve stale knowledge. The embedded
// knowledge is used only when no store exists or when the caller forces it.
//
// Revisions of the embedded knowledge (a dated label) and of a signed
// database (a whole number) have no common order, so the embedded knowledge
// is never preferred because it "looks newer": a verified database in the
// default location wins.
package knowledgeauto

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

// Profile is the knowledge profile whose store lives in the default location.
const Profile = "cncf-projects"

// Names of the knowledge sources a report may state.
const (
	SourceEmbedded = "embedded"
	SourceLocalDB  = "local-db"
)

// Flag values of --knowledge.
const (
	ModeAuto     = "auto"
	ModeEmbedded = "embedded"
)

// ErrRefused marks a present but unusable default store.
var ErrRefused = errors.New("default knowledge database refused")

// Refused is a default store that exists but cannot be used. Reason is a
// short class that never names a path.
type Refused struct{ Reason string }

func (e *Refused) Error() string {
	return fmt.Sprintf("KNOWLEDGE INTEGRITY FAILURE: the local knowledge database in the default store is present but cannot be used (%s); nothing was evaluated and the embedded knowledge was not used. "+
		"Repair it with `prufyx db update`, remove it, or force the embedded knowledge with --knowledge=embedded", e.Reason)
}

// Unwrap makes a Refused match ErrRefused.
func (e *Refused) Unwrap() error { return ErrRefused }

// DefaultRoot is the default store directory: $XDG_DATA_HOME/prufyx/knowledge/cncf-projects
// when XDG_DATA_HOME is an absolute path, else ~/.local/share/prufyx/knowledge/cncf-projects.
// ok is false when no absolute location can be determined.
func DefaultRoot() (root string, ok bool) {
	base := os.Getenv("XDG_DATA_HOME")
	if !filepath.IsAbs(base) {
		home, err := os.UserHomeDir()
		if err != nil || !filepath.IsAbs(home) {
			return "", false
		}
		base = filepath.Join(home, ".local", "share")
	}
	return filepath.Join(base, "prufyx", "knowledge", Profile), true
}

// maxMissingLevels bounds how many missing directories EnsureRoot creates.
const maxMissingLevels = 8

// EnsureRoot creates the default store directory and its missing parents
// below the first existing ancestor, each private to the owner (0700)
// whatever the process umask is, and returns it. Existing directories are not
// changed. A symbolic link at the first existing ancestor, or anywhere among
// the directories it creates, is refused.
func EnsureRoot() (string, error) {
	root, ok := DefaultRoot()
	if !ok {
		return "", errors.New("no default knowledge database location")
	}
	var missing []string
	for dir := root; ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err == nil {
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
				return "", errors.New("default knowledge database location has a parent that is not a real directory")
			}
			break
		} else if !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
		missing = append(missing, dir)
		if len(missing) > maxMissingLevels || filepath.Dir(dir) == dir {
			return "", errors.New("default knowledge database location has no existing parent")
		}
	}
	for i := len(missing) - 1; i >= 0; i-- {
		if err := os.Mkdir(missing[i], 0o700); err != nil {
			return "", err
		}
		info, err := os.Lstat(missing[i])
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return "", errors.New("default knowledge database location changed while it was created")
		}
		if err := os.Chmod(missing[i], 0o700); err != nil {
			return "", err
		}
	}
	return root, nil
}

var markers = []string{"profile.json", "selection.json", "import-pending.json"}

// committedMarkers exist only once an import has begun committing: a selected
// revision or a pending import. Their presence makes a store present whatever
// else it holds.
var committedMarkers = []string{"selection.json", "import-pending.json"}

// bootstrapArtefacts are what a first import that never committed a revision
// leaves behind: the lock, the profile marker, the clock floor and the trust
// directory. A directory that holds only these (and neither a selection nor a
// pending import) has no committed state and counts as absent; deleting it
// would change nothing.
var bootstrapArtefacts = map[string]bool{".lock": true, "profile.json": true, "clock-floor.json": true, "trust": true}

func neverCommitted(root string, entries []os.DirEntry) bool {
	for _, entry := range entries {
		if !bootstrapArtefacts[entry.Name()] {
			return false
		}
		info, err := os.Lstat(filepath.Join(root, entry.Name()))
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return false
		}
		if entry.Name() == "trust" != info.IsDir() || (entry.Name() != "trust" && !info.Mode().IsRegular()) {
			return false
		}
	}
	return true
}

// Locate reports whether a default store exists. present is false when there
// is no store (nothing at the location, or an empty directory). A store that
// exists in an unusable shape (symbolic link, not a directory, not mode 0700,
// no store files) is returned as present with a *Refused error. Locate
// writes nothing.
func Locate() (root string, present bool, err error) {
	root, ok := DefaultRoot()
	if !ok {
		return "", false, nil
	}
	info, statErr := os.Lstat(root)
	switch {
	case errors.Is(statErr, fs.ErrNotExist), isNotDir(statErr):
		return root, false, nil
	case statErr != nil:
		return root, true, &Refused{Reason: "the store location cannot be read"}
	case info.Mode()&os.ModeSymlink != 0, !info.IsDir(), info.Mode().Perm() != 0o700:
		return root, true, &Refused{Reason: "the store must be a real directory private to its owner (mode 0700)"}
	}
	entries, readErr := os.ReadDir(root)
	if readErr != nil {
		return root, true, &Refused{Reason: "the store location cannot be read"}
	}
	if len(entries) == 0 {
		return root, false, nil
	}
	for _, name := range committedMarkers {
		if marker, err := os.Lstat(filepath.Join(root, name)); err == nil && marker.Mode().IsRegular() {
			return root, true, nil
		}
	}
	if neverCommitted(root, entries) {
		return root, false, nil
	}
	for _, name := range markers {
		if marker, err := os.Lstat(filepath.Join(root, name)); err == nil && marker.Mode().IsRegular() {
			return root, true, nil
		}
	}
	return root, true, &Refused{Reason: "the directory is not a knowledge database"}
}

func isNotDir(err error) bool {
	var pathErr *fs.PathError
	return errors.As(err, &pathErr) && errors.Is(pathErr.Err, syscall.ENOTDIR)
}

// Reason names the class of a store verification failure. It never names a
// path or key.
func Reason(err error) string {
	switch {
	case errors.Is(err, knowledge.ErrNoSelection):
		return "no verified revision is selected"
	case errors.Is(err, knowledge.ErrExpired):
		return "the signed metadata has expired; run `prufyx db update`"
	case errors.Is(err, knowledge.ErrRollback):
		return "rollback or clock rollback rejected"
	case errors.Is(err, knowledge.ErrTrustAdvanced):
		return "the trusted state changed"
	case errors.Is(err, knowledge.ErrRecoveryRequired):
		return "an interrupted import needs recovery"
	case errors.Is(err, knowledge.ErrLayout):
		return "the database layout does not match its profile marker"
	}
	return "verification failed"
}

// CheckPin refuses a store whose initial root is not the product pin. An
// empty pin accepts any root that the store verification already accepted.
func CheckPin(pin, initialRootDigest string) error {
	if pin == "" {
		return nil
	}
	if strings.TrimPrefix(pin, "sha256:") != strings.TrimPrefix(initialRootDigest, "sha256:") || initialRootDigest == "" {
		return &Refused{Reason: "its trust root is not the root pinned in this build"}
	}
	return nil
}

// StalenessNote is the standard-error note that makes the age of a database
// in use visible. Until the embedded knowledge and a database can be compared
// (FEED-1b) a verified database always wins, however old it is. It changes no
// verdict.
func StalenessNote(verifiedAt, evidenceExpiresAt string) string {
	note := "local database last verified at " + verifiedAt
	if evidenceExpiresAt != "" {
		note += ", signed evidence expires " + evidenceExpiresAt
	}
	return note + "; it is used even when older than the embedded knowledge (no freshness comparison yet)"
}
