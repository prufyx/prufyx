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

	// pending lists alarms added since the last Save, to be written to the
	// dated alarm files.
	pending []Alarm
	// digest identifies the exact index file this value was loaded from.
	digest string
}

// Digest is a short hex digest of the index file as it was loaded: it
// changes whenever the mirror records anything new. It is empty for an
// index that has not been written yet.
func (idx *Index) Digest() string { return idx.digest }

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
	// Tombstones maps a tag that disappeared upstream to the commit it last
	// pointed at. A tombstoned tag that reappears at another commit raises
	// an alarm.
	Tombstones map[string]string `json:"tombstones,omitempty"`
	// Frozen is true while the repository has an unacknowledged alarm.
	// Loosening changes that depend on this repository must not be made
	// while it is frozen.
	Frozen bool `json:"frozen"`
}

// Alarm kinds.
const (
	AlarmTagMoved   = "tag_moved"
	AlarmTagDeleted = "tag_deleted"
	// AlarmTagReappeared is a deleted tag that came back at another commit.
	AlarmTagReappeared = "tag_reappeared"
)

// AlarmsSchema identifies the dated alarm files in the alarms directory.
const AlarmsSchema = "prufyx.io/factory-mirror-alarms/v1"

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
	sum := sha256.Sum256(raw)
	idx.digest = hex.EncodeToString(sum[:8])
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

// addAlarm records a newly detected alarm.
func (idx *Index) addAlarm(a Alarm) {
	idx.Alarms = append(idx.Alarms, a)
	idx.pending = append(idx.pending, a)
}

// alarmsFile is the content of alarms/<date>.json: the alarms detected that
// (UTC) day, as they were when detected. It is an append-only feed for the
// monitor; acknowledgement state lives in the index.
type alarmsFile struct {
	Schema string  `json:"schema"`
	Date   string  `json:"date"`
	Alarms []Alarm `json:"alarms"`
}

func (idx *Index) flushAlarmFiles(stateDir string) error {
	byDate := map[string][]Alarm{}
	for _, a := range idx.pending {
		date := a.DetectedAt
		if len(date) >= 10 {
			date = date[:10]
		}
		byDate[date] = append(byDate[date], a)
	}
	for date, fresh := range byDate {
		path := filepath.Join(stateDir, "alarms", date+".json")
		doc := alarmsFile{Schema: AlarmsSchema, Date: date, Alarms: []Alarm{}}
		if raw, err := os.ReadFile(path); err == nil {
			var old alarmsFile
			if json.Unmarshal(raw, &old) == nil && old.Schema == AlarmsSchema {
				doc.Alarms = old.Alarms
			}
		}
		for _, a := range fresh {
			dup := false
			for _, o := range doc.Alarms {
				if o.ID == a.ID {
					dup = true
				}
			}
			if !dup {
				doc.Alarms = append(doc.Alarms, a)
			}
		}
		raw, err := json.MarshalIndent(doc, "", "  ")
		if err != nil {
			return err
		}
		if err := writeFileAtomic(path, append(raw, '\n')); err != nil {
			return err
		}
	}
	idx.pending = nil
	return nil
}

// Save writes the index atomically, after the dated alarm files of newly
// detected alarms.
func (idx *Index) Save(stateDir string) error {
	if err := idx.flushAlarmFiles(stateDir); err != nil {
		return err
	}
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
// tombstones holds tags that were seen deleted earlier and their last commit.
func detectTagChanges(repo string, old map[string]TagInfo, tombstones map[string]string, current map[string]TagInfo, now string) []Alarm {
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
	names = names[:0]
	for n := range tombstones {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		last := tombstones[n]
		cur, ok := current[n]
		if _, tracked := old[n]; ok && !tracked && cur.Commit != last {
			out = append(out, Alarm{ID: alarmID(AlarmTagReappeared, repo, n, last, cur.Commit), Kind: AlarmTagReappeared, Repo: repo, Tag: n, OldCommit: last, NewCommit: cur.Commit, DetectedAt: now})
		}
	}
	return out
}

// nextTombstones returns the tombstones after moving from old to current:
// tags that vanished are added, tags that are present are dropped.
func nextTombstones(old map[string]TagInfo, tombstones map[string]string, current map[string]TagInfo) map[string]string {
	out := map[string]string{}
	for n, c := range tombstones {
		if _, back := current[n]; !back {
			out[n] = c
		}
	}
	for n, t := range old {
		if _, still := current[n]; !still {
			out[n] = t.Commit
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func sortStrings(lists ...[]string) {
	for _, l := range lists {
		sort.Strings(l)
	}
}
