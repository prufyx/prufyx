// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"bytes"
	"encoding/json"
	"time"

	"github.com/prufyx/prufyx/cli/internal/distribution"
	"github.com/prufyx/prufyx/cli/internal/k8sversion"
	"github.com/prufyx/prufyx/cli/internal/lineattest"
)

// admitDistributions locates the pack's distribution section by its exact
// member name (lineattest.PackMemberSection), requires the decoded field to
// hold exactly those bytes, and parses it strictly. Any problem rejects the
// whole pack. A pack without the section admits an empty index, under
// which only upstream-equivalent distributions are checked as upstream.
func admitDistributions(packRaw []byte, field json.RawMessage) (distribution.Index, error) {
	section, present, err := lineattest.PackMemberSection(packRaw, distribution.PackMember)
	if err != nil || present != (len(field) > 0) || !bytes.Equal(section, field) {
		return distribution.Index{}, ErrIntegrity
	}
	if !present {
		return distribution.NewIndex(distribution.Section{}), nil
	}
	parsed, err := distribution.Parse(section)
	if err != nil {
		return distribution.Index{}, ErrIntegrity
	}
	return distribution.NewIndex(parsed), nil
}

// DistributionApplicability answers, from the embedded pack, whether a rule
// family applies to a distribution at now. Only a result whose Applies is
// true may be checked as upstream; everything else (no record, no
// statement, not_applicable, not current) is a gap.
func DistributionApplicability(distributionID, family string, now time.Time) (distribution.ApplicabilityStatus, error) {
	b, err := load()
	if err != nil {
		return distribution.ApplicabilityStatus{}, err
	}
	return b.distributions.ApplicabilityFor(distributionID, family, now), nil
}

// OpenShiftMinor returns, from the embedded pack, the Kubernetes line an
// OpenShift line is based on, with the record's freshness at now. Only
// MappingStatus.Minor may be used.
func OpenShiftMinor(line string, now time.Time) (distribution.MappingStatus, error) {
	b, err := load()
	if err != nil {
		return distribution.MappingStatus{}, err
	}
	return b.distributions.OpenShiftMinor(line, now), nil
}

// OpenShiftTable is the embedded pack's OpenShift mapping as
// k8sversion.ParseWith reads it: nil unless a current record maps a line.
func OpenShiftTable(now time.Time) (k8sversion.OpenShiftMap, error) {
	b, err := load()
	if err != nil {
		return nil, err
	}
	return b.distributions.OpenShiftTable(now), nil
}
