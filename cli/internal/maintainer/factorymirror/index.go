// SPDX-License-Identifier: AGPL-3.0-only

package factorymirror

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
)

// IndexSchema identifies mirror-index.json.
const IndexSchema = "prufyx.io/factory-mirror-index/v1"

const maxIndexBytes int64 = 256 << 20

// Index is the persistent record of what the mirror knows.
type Index struct {
	Schema    string               `json:"schema"`
	UpdatedAt string               `json:"updatedAt"`
	Repos     map[string]*RepoInfo `json:"repos"`
	Alarms    []Alarm              `json:"alarms"`
}

// RepoInfo is the mirror's knowledge of one repository.
type RepoInfo struct {
	Host  string `json:"host"`
	Owner string `json:"owner"`
	Name  string `json:"name"`
	Path  string `json:"path"`
	// Status is "ok" after a successful check, "error" after a failed one
	// (the previous refs below are then the last good state).
	Status            string             `json:"status"`
	Error             string             `json:"error,omitempty"`
	RemoteFingerprint string             `json:"remoteFingerprint,omitempty"`
	LastCheckedAt     string             `json:"lastCheckedAt,omitempty"`
	LastFetchedAt     string             `json:"lastFetchedAt,omitempty"`
	Heads             map[string]string  `json:"heads,omitempty"`
	Tags              map[string]TagInfo `json:"tags,omitempty"`
	Releases          Releases           `json:"releases"`
	// Frozen is true while the repository has an unacknowledged alarm.
	// Loosening changes that depend on this repository must not be made
	// while it is frozen.
	Frozen bool `json:"frozen"`
}

// Alarm kinds.
const (
	AlarmTagMoved   = "tag_moved"
	AlarmTagDeleted = "tag_deleted"
)

// Alarm is a durable record of upstream behaviour that must not be trusted
// silently.
type Alarm struct {
	ID             string `json:"id"`
	Kind           string `json:"kind"`
	Repo           string `json:"repo"`
	Tag            string `json:"tag"`
	OldCommit      string `json:"oldCommit"`
	NewCommit      string `json:"newCommit,omitempty"`
	DetectedAt     string `json:"detectedAt"`
	Acknowledged   bool   `json:"acknowledged"`
	AcknowledgedAt string `json:"acknowledgedAt,omitempty"`
	Note           string `json:"note,omitempty"`
}

func alarmID(kind, repo, tag, oldCommit, newCommit string) string {
	sum := sha256.Sum256([]byte(kind + "\x00" + repo + "\x00" + tag + "\x00" + oldCommit + "\x00" + newCommit))
	return hex.EncodeToString(sum[:8])
}

func newIndex() *Index {
	return &Index{Schema: IndexSchema, Repos: map[string]*RepoInfo{}, Alarms: []Alarm{}}
}

// LoadIndex reads mirror-index.json from the state directory. A missing file
// yields an empty index.
func LoadIndex(stateDir string) (*Index, error) {
	f, err := os.Open(filepath.Join(stateDir, "mirror-index.json"))
	if errors.Is(err, os.ErrNotExist) {
		return newIndex(), nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, maxIndexBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > maxIndexBytes {
		return nil, fmt.Errorf("%w: mirror index too large", ErrInvalid)
	}
	idx := newIndex()
	if err := json.Unmarshal(raw, idx); err != nil {
		return nil, fmt.Errorf("%w: mirror index: %v", ErrInvalid, err)
	}
	if idx.Schema != IndexSchema {
		return nil, fmt.Errorf("%w: mirror index schema %q", ErrInvalid, idx.Schema)
	}
	if idx.Repos == nil {
		idx.Repos = map[string]*RepoInfo{}
	}
	if idx.Alarms == nil {
		idx.Alarms = []Alarm{}
	}
	return idx, nil
}

// Save writes the index atomically.
func (idx *Index) Save(stateDir string) error {
	for _, info := range idx.Repos {
		info.Frozen = false
	}
	for _, a := range idx.Alarms {
		if !a.Acknowledged {
			if info := idx.Repos[a.Repo]; info != nil {
				info.Frozen = true
			}
		}
	}
	sort.SliceStable(idx.Alarms, func(i, j int) bool {
		if idx.Alarms[i].DetectedAt != idx.Alarms[j].DetectedAt {
			return idx.Alarms[i].DetectedAt < idx.Alarms[j].DetectedAt
		}
		return idx.Alarms[i].ID < idx.Alarms[j].ID
	})
	raw, err := json.MarshalIndent(idx, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(stateDir, "mirror-index.json"), append(raw, '\n'))
}

// OpenAlarms returns the unacknowledged alarms.
func (idx *Index) OpenAlarms() []Alarm {
	var out []Alarm
	for _, a := range idx.Alarms {
		if !a.Acknowledged {
			out = append(out, a)
		}
	}
	return out
}

func (idx *Index) hasAlarm(id string) bool {
	for _, a := range idx.Alarms {
		if a.ID == id {
			return true
		}
	}
	return false
}

func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Chmod(name, 0o644); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}

// detectTagChanges compares previously recorded tags with a new view.
func detectTagChanges(repo string, old map[string]TagInfo, current map[string]TagInfo, now string) []Alarm {
	var out []Alarm
	names := make([]string, 0, len(old))
	for n := range old {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		prev := old[n]
		cur, ok := current[n]
		switch {
		case !ok:
			out = append(out, Alarm{ID: alarmID(AlarmTagDeleted, repo, n, prev.Commit, ""), Kind: AlarmTagDeleted, Repo: repo, Tag: n, OldCommit: prev.Commit, DetectedAt: now})
		case cur.Commit != prev.Commit:
			out = append(out, Alarm{ID: alarmID(AlarmTagMoved, repo, n, prev.Commit, cur.Commit), Kind: AlarmTagMoved, Repo: repo, Tag: n, OldCommit: prev.Commit, NewCommit: cur.Commit, DetectedAt: now})
		}
	}
	return out
}

func sortStrings(lists ...[]string) {
	for _, l := range lists {
		sort.Strings(l)
	}
}
