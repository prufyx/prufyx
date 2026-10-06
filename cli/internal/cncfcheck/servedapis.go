// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
)

// admitServedAPIs locates the pack's served-list section by its exact member
// name (lineattest.PackMemberSection), requires the decoded field to hold
// exactly those bytes, parses it strictly and requires every record's
// component to be the subject component of a catalog project. Any problem
// rejects the whole pack. A pack without the section admits an empty index:
// every Kubernetes API group object is then a named gap in scan.
func admitServedAPIs(packRaw []byte, field json.RawMessage, projects []projectIdentity) (servedapis.Index, error) {
	section, present, err := lineattest.PackMemberSection(packRaw, servedapis.PackMember)
	if err != nil || present != (len(field) > 0) || !bytes.Equal(section, field) {
		return servedapis.Index{}, ErrIntegrity
	}
	if !present {
		return servedapis.NewIndex(nil), nil
	}
	records, err := servedapis.Parse(section)
	if err != nil {
		return servedapis.Index{}, ErrIntegrity
	}
	subjects := subjectComponents(projects)
	for _, record := range records {
		if !subjects[record.Component] {
			return servedapis.Index{}, ErrIntegrity
		}
	}
	return servedapis.NewIndex(records), nil
}

// ServedAPIsFor is the served-API list lookup over this snapshot, with the
// contract of servedapis.Index.For: only a current record may be relied on.
func (k *ScanKnowledge) ServedAPIsFor(component, line string, now time.Time) (servedapis.Status, bool) {
	b, ok := k.bundleForComponent(component)
	if !ok {
		return servedapis.Status{}, false
	}
	return b.servedAPIs.For(component, line, now)
}
