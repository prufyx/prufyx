// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/prufyx/prufyx/cli/internal/k8sremovals"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
)

// admitServedAPIs locates the pack's served-list section by its exact member
// name (lineattest.PackMemberSection), requires the decoded field to hold
// exactly those bytes, parses it strictly and requires every record's
// component to be the subject component of a catalog project. Any problem
// rejects the whole pack, including a list for line L that names an API the
// removal table marks as removed on a line at or below L: the table is the
// binary's own knowledge, and a list contradicting it must not decide a scan.
// A pack without the section admits an empty index:
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
	removed := k8sremovals.AdmissionRemovedVersions()
	for _, record := range records {
		if !subjects[record.Component] || namesRemovedAPI(record, removed) {
			return servedapis.Index{}, ErrIntegrity
		}
	}
	return servedapis.NewIndex(records), nil
}

// namesRemovedAPI reports whether the served list of line L names any
// "group/version kind" the removal table marks as removed at a line <= L.
func namesRemovedAPI(record servedapis.Record, removed []k8sremovals.RemovedVersion) bool {
	for _, removal := range removed {
		if lineattest.LineLess(record.Line, removal.Line) {
			continue
		}
		prefix := removal.Version + " "
		if removal.Group != "" {
			prefix = removal.Group + "/" + removal.Version + " "
		}
		for _, kind := range removal.Kinds {
			for _, api := range record.APIs {
				if api == prefix+kind {
					return true
				}
			}
		}
	}
	return false
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
