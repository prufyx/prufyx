// SPDX-License-Identifier: AGPL-3.0-only

package cncfcheck

import (
	"time"

	"github.com/prufyx/prufyx/cli/internal/lineattest"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
	"github.com/prufyx/prufyx/cli/internal/upgradepath"
)

// A withdrawn record binds a store like a withdrawn rule does
// (embedded_withdrawal.go): a store record of the same scope stays in force
// only when its evidence.reviewedAt is strictly after the review the
// withdrawal stands on. Nothing else brings it back.
//
// A path policy is withdrawn in the embedded pack by its evidence.state. A
// store record it binds is withdrawn, and a store that holds no record for
// the component gets the embedded withdrawn one: without any record a path is
// planned as one direct hop.
//
// A line attestation and a served-API list have no evidence state: removing
// the record from the pack is how it is withdrawn, so the pack cannot say
// what it removed. compiledRecordWithdrawals says it. A change that removes
// such a record from the embedded pack must add its scope there, with the
// removed record's reviewedAt. A store record it binds is dropped, which
// leaves the line a named gap.

// servedScope identifies a served-API list.
type servedScope struct{ component, line string }

// recordWithdrawals are the removed line attestations and served-API lists,
// each with the reviewedAt of the record that was removed.
type recordWithdrawals struct {
	attestations map[lineattest.Key]string
	servedLists  map[servedScope]string
}

// compiledRecordWithdrawals lists what this build removed. No record has been
// removed yet.
var compiledRecordWithdrawals = recordWithdrawals{
	attestations: map[lineattest.Key]string{},
	servedLists:  map[servedScope]string{},
}

// reviewTime parses a whole-second UTC (RFC 3339 with Z) review time.
func reviewTime(value string) (time.Time, error) {
	at, err := time.Parse(time.RFC3339, value)
	if err != nil || at.UTC().Format(time.RFC3339) != value {
		return time.Time{}, ErrIntegrity
	}
	return at, nil
}

// reviewedAfter reports whether review is strictly after withdrawn. A time
// that cannot be read is an integrity failure.
func reviewedAfter(review, withdrawn string) (bool, error) {
	at, err := reviewTime(review)
	if err != nil {
		return false, err
	}
	end, err := reviewTime(withdrawn)
	if err != nil {
		return false, err
	}
	return at.After(end), nil
}

// bindRecordWithdrawals replaces the record indexes of a bundle selected from
// a store for project with indexes under the withdrawals of the embedded pack
// and of removed. external is the admitted store pack; it is not changed.
func bindRecordWithdrawals(selected *bundle, embedded, external rulePack, project projectIdentity, removed recordWithdrawals) error {
	attestations, err := attestationsNotWithdrawn(external, removed.attestations)
	if err != nil {
		return err
	}
	policies, err := policiesUnderWithdrawals(embedded, external, project)
	if err != nil {
		return err
	}
	served, err := servedListsNotWithdrawn(external, removed.servedLists)
	if err != nil {
		return err
	}
	selected.attestations = lineattest.NewIndex(attestations)
	selected.pathPolicies = upgradepath.NewIndex(policies)
	selected.servedAPIs = servedapis.NewIndex(served)
	return nil
}

func attestationsNotWithdrawn(external rulePack, removed map[lineattest.Key]string) ([]lineattest.LineAttestation, error) {
	if len(external.LineAttestations) == 0 {
		return nil, nil
	}
	records, err := lineattest.Parse(external.LineAttestations)
	if err != nil {
		return nil, ErrIntegrity
	}
	var kept []lineattest.LineAttestation
	for _, record := range records {
		if withdrawn, held := removed[record.Key()]; held {
			newer, err := reviewedAfter(record.Evidence.ReviewedAt, withdrawn)
			if err != nil {
				return nil, err
			}
			if !newer {
				continue
			}
		}
		kept = append(kept, record)
	}
	return kept, nil
}

func servedListsNotWithdrawn(external rulePack, removed map[servedScope]string) ([]servedapis.Record, error) {
	if len(external.ServedAPIs) == 0 {
		return nil, nil
	}
	records, err := servedapis.Parse(external.ServedAPIs)
	if err != nil {
		return nil, ErrIntegrity
	}
	var kept []servedapis.Record
	for _, record := range records {
		if withdrawn, held := removed[servedScope{record.Component, record.Line}]; held {
			newer, err := reviewedAfter(record.Evidence.ReviewedAt, withdrawn)
			if err != nil {
				return nil, err
			}
			if !newer {
				continue
			}
		}
		kept = append(kept, record)
	}
	return kept, nil
}

func policiesUnderWithdrawals(embedded, external rulePack, project projectIdentity) ([]upgradepath.Record, error) {
	parse := func(pack rulePack) ([]upgradepath.Record, error) {
		if len(pack.PathPolicies) == 0 {
			return nil, nil
		}
		records, err := upgradepath.Parse(pack.PathPolicies)
		if err != nil {
			return nil, ErrIntegrity
		}
		return records, nil
	}
	own, err := parse(embedded)
	if err != nil {
		return nil, err
	}
	records, err := parse(external)
	if err != nil {
		return nil, err
	}
	withdrawn := map[string]upgradepath.Record{}
	for _, record := range own {
		if record.Evidence.State == upgradepath.StateWithdrawn {
			withdrawn[record.Component] = record
		}
	}
	held := map[string]bool{}
	for i, record := range records {
		held[record.Component] = true
		gone, bound := withdrawn[record.Component]
		if !bound {
			continue
		}
		newer, err := reviewedAfter(record.Evidence.ReviewedAt, gone.Evidence.ReviewedAt)
		if err != nil {
			return nil, err
		}
		if !newer {
			records[i].Evidence.State = upgradepath.StateWithdrawn
		}
	}
	for _, component := range projectComponents(project) {
		if gone, bound := withdrawn[component]; bound && !held[component] {
			records = append(records, gone)
		}
	}
	return records, nil
}
