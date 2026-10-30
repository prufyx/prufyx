// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgeauto decides, without reading any clock or network,
// whether a command uses the verified knowledge database that `prufyx db
// update` installs in the default store location, or the knowledge built
// into the binary.
//
// The rule is fail-closed. No default store means embedded knowledge. A
// default store that is present but cannot be used (damaged, unverifiable,
// rolled back, private-mode wrong, or rooted in a different trust root than
// the product pin) is an error: it never falls back silently, because that
// could hide tampering. The one exception is a store whose signed metadata
// has merely expired: that store is not used, the embedded knowledge is, and
// the fallback is announced.
//
// A store that verifies is compared with the embedded knowledge by the latest
// evidence review date in each (Choose): the newer knowledge wins. On a tie
// the embedded knowledge is used when the store holds identical content, and
// the store when its content differs, which is a later correction.
package knowledgeauto

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

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
// changed. The first existing ancestor may be a symbolic link to a directory;
// a symbolic link among the directories it creates is refused.
func EnsureRoot() (string, error) {
	root, ok := DefaultRoot()
	if !ok {
		return "", errors.New("no default knowledge database location")
	}
	var missing []string
	for dir := root; ; dir = filepath.Dir(dir) {
		info, err := os.Lstat(dir)
		if err == nil {
			// The first existing ancestor may be (or be below) a symbolic
			// link, as Locate and the store layer accept for the base; it
			// must resolve to a directory. Links are refused only among the
			// directories created below.
			if info.Mode()&os.ModeSymlink != 0 {
				info, err = os.Stat(dir)
				if err != nil {
					return "", errors.New("default knowledge database location has a parent that cannot be read")
				}
			}
			if !info.IsDir() {
				return "", errors.New("default knowledge database location has a parent that is not a directory")
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
// in use visible. It is printed only when the database was chosen because its
// evidence is newer than the embedded knowledge. It changes no verdict.
func StalenessNote(verifiedAt, evidenceExpiresAt string) string {
	note := "local database last verified at " + verifiedAt
	if evidenceExpiresAt != "" {
		note += ", signed evidence expires " + evidenceExpiresAt
	}
	return note + "; it is used because its evidence is newer than the embedded knowledge"
}

// Reasons of a knowledge selection, as stated in a report.
const (
	ReasonStoreNewer = "store-newer"
	// ReasonStoreCorrected is a store with the same evidence date as the
	// embedded knowledge but different content.
	ReasonStoreCorrected = "store-corrected"
	ReasonStoreOlder     = "store-older"
	ReasonIdentical      = "identical"
	ReasonNoStore        = "no-store"
	ReasonForced         = "forced"
	ReasonStoreExpired   = "store-expired"
	// ReasonStoreTooNew is a store the pinned root signed but this build
	// cannot read; ReasonStoreTrustAdvanced one that an older client left
	// with a trust state this build cannot advance.
	ReasonStoreTooNew        = "store-too-new"
	ReasonStoreTrustAdvanced = "store-trust-advanced"
)

// Selection is the outcome of choosing between a verified store and the
// embedded knowledge.
type Selection struct {
	Chosen     string
	Reason     string
	StoreAt    time.Time
	EmbeddedAt time.Time
	// StaleProject is the project whose store evidence is older than the
	// embedded one; it makes the embedded knowledge win whatever the others say.
	StaleProject string
}

// Choose picks the newer knowledge by its latest evidence review date. The
// store is used only when no compared project has older evidence in it than in
// the embedded knowledge (staleProject names the first that has; storeAt and
// embeddedAt are then that project's dates). On an equal date the embedded
// knowledge is used when the store's content is identical, otherwise the
// store (the same date with different content is a later correction).
func Choose(storeAt, embeddedAt time.Time, identical bool, staleProject string) Selection {
	s := Selection{StoreAt: storeAt, EmbeddedAt: embeddedAt, StaleProject: staleProject}
	switch {
	case staleProject != "":
		s.Chosen, s.Reason = SourceEmbedded, ReasonStoreOlder
	case storeAt.After(embeddedAt):
		s.Chosen, s.Reason = SourceLocalDB, ReasonStoreNewer
	case storeAt.Before(embeddedAt):
		s.Chosen, s.Reason = SourceEmbedded, ReasonStoreOlder
	case identical:
		s.Chosen, s.Reason = SourceEmbedded, ReasonIdentical
	default:
		s.Chosen, s.Reason = SourceLocalDB, ReasonStoreCorrected
	}
	return s
}

// UseStore reports whether the verified store is the knowledge to use.
func (s Selection) UseStore() bool { return s.Chosen == SourceLocalDB }

func day(t time.Time) string { return t.UTC().Format("2006-01-02") }

// StoreDetail is the parenthesis that follows the line of a chosen store.
func (s Selection) StoreDetail() string {
	if s.StoreAt.Equal(s.EmbeddedAt) {
		return "same evidence date " + day(s.StoreAt) + ", content differs from embedded: a later correction"
	}
	return "newer than embedded: evidence " + day(s.StoreAt) + " vs " + day(s.EmbeddedAt)
}

// EmbeddedWhy is the reason text of a chosen embedded knowledge.
func (s Selection) EmbeddedWhy() string {
	if s.Reason == ReasonIdentical {
		return "local database identical to embedded (evidence " + day(s.StoreAt) + "); embedded used"
	}
	project := ""
	if s.StaleProject != "" {
		project = " for " + s.StaleProject
	}
	return "local database is older" + project + " (evidence " + day(s.StoreAt) + " vs " + day(s.EmbeddedAt) + "); run `prufyx db update`"
}

// ExpiredWhy is the reason text of the embedded fallback for an expired store.
const ExpiredWhy = "the local database's signed metadata has expired; run `prufyx db update`"

// FallbackReason reports whether a store failure is one of the few that fall
// back to the embedded knowledge (with a warning), and the reason to state.
// It is the single place such a failure is added. Only a store whose signed
// metadata has expired, one the pinned root signed but this build cannot read
// (ErrUnsupportedKnowledge), or one left with an unadvanceable trust state
// (ErrTrustAdvanced) qualifies, and only when no integrity, rollback,
// selection, layout or recovery failure is part of the error.
func FallbackReason(err error) (reason string, ok bool) {
	hard := errors.Is(err, knowledge.ErrIntegrity) || errors.Is(err, knowledge.ErrRollback) ||
		errors.Is(err, knowledge.ErrNoSelection) ||
		errors.Is(err, knowledge.ErrLayout) || errors.Is(err, knowledge.ErrRecoveryRequired)
	switch {
	case hard:
		return "", false
	case errors.Is(err, knowledge.ErrExpired):
		return ReasonStoreExpired, true
	case errors.Is(err, knowledge.ErrUnsupportedKnowledge):
		return ReasonStoreTooNew, true
	case errors.Is(err, knowledge.ErrTrustAdvanced):
		return ReasonStoreTrustAdvanced, true
	}
	return "", false
}

// FallbackWhy is the warning text of the embedded fallback for a reason that
// FallbackReason returned, without the details FallbackWarning adds.
func FallbackWhy(reason string) string { return FallbackWarning(reason, "", "") }

// FallbackWarning is FallbackWhy with the minimum prufyx version the knowledge
// names (store-too-new) and the store directory (store-trust-advanced), each
// when known. The store is never removed by prufyx.
func FallbackWarning(reason, minVersion, storeDir string) string {
	switch reason {
	case ReasonStoreExpired:
		return ExpiredWhy
	case ReasonStoreTooNew:
		why := "the local database cannot be used: a newer prufyx is needed for this knowledge"
		if minVersion != "" {
			why += " (min version " + minVersion + ")"
		}
		return why
	case ReasonStoreTrustAdvanced:
		dir := "the local database directory"
		if storeDir != "" {
			dir = storeDir
		}
		return "the local database cannot be advanced by this version of prufyx: upgrade prufyx, or remove " + dir + " and run `prufyx db update`"
	}
	return "the local database cannot be used; run `prufyx db update`"
}
