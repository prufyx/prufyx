// SPDX-License-Identifier: AGPL-3.0-only

package contribution

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
)

var candidateNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*\.json$`)

func ValidateCandidates(directory, landscape string) ([]byte, error) {
	info, e := os.Lstat(directory)
	if e != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrRejected
	}
	entries, e := os.ReadDir(directory)
	if e != nil {
		return nil, ErrRejected
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	digests := []any{}
	for _, entry := range entries {
		if entry.Name() == "negative" {
			i, e := entry.Info()
			if e != nil || !i.IsDir() || i.Mode()&os.ModeSymlink != 0 {
				return nil, ErrRejected
			}
			continue
		}
		i, e := entry.Info()
		if e != nil || !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 || !candidateNameRE.MatchString(entry.Name()) || i.Size() > MaxPacketBytes {
			return nil, ErrRejected
		}
		raw, e := safeRead(filepath.Join(directory, entry.Name()), MaxPacketBytes)
		if e != nil {
			return nil, e
		}
		v, e := decode(raw, MaxPacketBytes)
		if e != nil {
			return nil, e
		}
		receipt, e := ValidatePacket(v, landscape)
		if e != nil {
			return nil, e
		}
		digests = append(digests, receipt["packetDigest"])
		if len(digests) > 64 {
			return nil, ErrRejected
		}
	}
	return canonical(map[string]any{"schema": "prufyx.io/upstream-evidence-candidate-summary/v1", "status": "PASS", "candidateCount": len(digests), "candidateDigests": digests, "workflowState": "CANDIDATE", "supportAdmission": "NOT_ADMITTED"}, true)
}
