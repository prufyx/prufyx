// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"encoding/json"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// NewestRecordLine is the newest release line of the component that a
// served-API list or a line review of this snapshot names, whatever its
// freshness, state, completeness or fact family; "" when none names one. It
// says nothing about whether the record can be used. A caller that picks a
// line from the current records compares against it, so that a record which
// expired or is incomplete is named instead of silently passed over. A
// snapshot that cannot answer is an error, never "no newer line".
func (k *ScanKnowledge) NewestRecordLine(component string) (string, error) {
	b, ok := k.bundleForComponent(component)
	if !ok {
		return "", ErrIntegrity
	}
	newest := ""
	for _, section := range []json.RawMessage{b.pack.ServedAPIs, b.pack.LineAttestations} {
		if len(section) == 0 {
			continue
		}
		var records []struct {
			Component string `json:"component"`
			Line      string `json:"line"`
		}
		if err := json.Unmarshal(section, &records); err != nil {
			return "", ErrIntegrity
		}
		for _, record := range records {
			if record.Component != component {
				continue
			}
			if !lineattest.ValidLine(record.Line) {
				return "", ErrIntegrity
			}
			if newest == "" || lineattest.LineLess(newest, record.Line) {
				newest = record.Line
			}
		}
	}
	return newest, nil
}
