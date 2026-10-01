// SPDX-License-Identifier: AGPL-3.0-only

package contribution

import (
	"bytes"
	"path/filepath"
	"sort"
	"strings"
)

func VerifySources(o ValidateOptions, sourceRoot string) ([]byte, error) {
	raw, err := safeRead(o.PacketPath, MaxPacketBytes)
	if err != nil {
		return nil, err
	}
	v, err := decode(raw, MaxPacketBytes)
	if err != nil {
		return nil, err
	}
	receipt, err := ValidatePacket(v, o.LandscapePath)
	if err != nil {
		return nil, err
	}
	sources := v.(map[string]any)["sources"].([]any)
	cache := map[string][]byte{}
	sourceCount, spanCount := 0, 0
	for _, item := range sources {
		source := item.(map[string]any)
		fd := source["fileDigest"].(string)
		data, ok := cache[fd]
		if !ok {
			data, err = safeRead(filepath.Join(sourceRoot, "sha256", strings.TrimPrefix(fd, "sha256:")), 16<<20)
			if err != nil || digest(data) != fd {
				return nil, ErrRejected
			}
			cache[fd] = data
		}
		sourceCount++
		for _, rawSpan := range source["spans"].([]any) {
			span := rawSpan.(map[string]any)
			start, _ := numberInt(span["startLine"])
			end, _ := numberInt(span["endLine"])
			excerpt := span["excerpt"].(string)
			selected, ok := selectLines(data, start, end)
			if !ok || string(selected) != excerpt {
				return nil, ErrRejected
			}
			spanCount++
		}
	}
	keys := make([]string, 0, len(cache))
	aggregate := 0
	for k, b := range cache {
		keys = append(keys, k)
		aggregate += len(b)
	}
	if aggregate > 16<<20 {
		return nil, ErrRejected
	}
	sort.Strings(keys)
	set := make([]any, len(keys))
	for i, k := range keys {
		set[i] = k
	}
	setRaw, err := canonical(set, false)
	if err != nil {
		return nil, err
	}
	return canonical(map[string]any{"schema": "prufyx.io/upstream-evidence-source-receipt/v1", "packetDigest": receipt["packetDigest"], "verification": "LOCAL_DECLARED_PUBLIC_SOURCE_BYTES_MATCHED", "workflowState": "CANDIDATE", "admissionState": "NOT_ADMITTED", "sourceCount": sourceCount, "uniqueObjectCount": len(cache), "spanCount": spanCount, "aggregateVerifiedByteLength": aggregate, "sourceSetDigest": digest(setRaw), "limitations": []any{"local supplied public bytes only; no upstream fetch, tag or ref authentication, contributor or reviewer authentication, or license determination", "matching bytes and excerpts do not approve semantic correctness, a rule, catalogue admission, signing, runtime behavior, or publication"}}, true)
}

func selectLines(data []byte, start, end int) ([]byte, bool) {
	if bytes.Contains(data, []byte{'\r'}) || start < 1 || end < start {
		return nil, false
	}
	lines := bytes.Split(data, []byte{'\n'})
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if end > len(lines) {
		return nil, false
	}
	return bytes.Join(lines[start-1:end], []byte{'\n'}), true
}
