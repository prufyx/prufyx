// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepacket

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
)

var mergeSubject = regexp.MustCompile(`^Merge pull request #([0-9]+) from `)

// Build assembles the packet. Any failure returns an error and no packet.
func Build(ctx context.Context, o Options) (*Packet, error) {
	if o.Repo == "" {
		return nil, errors.New("repository path is required")
	}
	if o.PreviousRevision < 0 {
		return nil, errors.New("previous revision must not be negative")
	}
	if err := validateInput(&o.Input); err != nil {
		return nil, err
	}
	trusted, err := newTrusted(o.TrustedUserIDs)
	if err != nil {
		return nil, err
	}
	r := repo{dir: o.Repo}
	base, err := r.resolve(ctx, o.Base)
	if err != nil {
		return nil, fmt.Errorf("base: %w", err)
	}
	head, err := r.resolve(ctx, o.Head)
	if err != nil {
		return nil, fmt.Errorf("head: %w", err)
	}
	ok, err := r.isAncestor(ctx, base, head)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, errors.New("base is not an ancestor of head")
	}
	inputs := map[int]*PRInput{}
	for i := range o.Input.PRs {
		inputs[o.Input.PRs[i].Number] = &o.Input.PRs[i]
	}

	merges, err := r.revList(ctx, base, head, true)
	if err != nil {
		return nil, err
	}
	direct, err := r.revList(ctx, base, head, false)
	if err != nil {
		return nil, err
	}
	p := &Packet{
		Schema:           PacketSchema,
		SourceCommit:     head,
		PreviousRevision: PreviousRevision{Revision: o.PreviousRevision, SourceCommit: base},
		Entries:          []Entry{},
		DirectCommits:    append([]string{}, direct...),
	}
	used := map[int]bool{}
	for _, m := range merges {
		e, err := entryFor(ctx, r, m, inputs, used, trusted)
		if err != nil {
			return nil, err
		}
		p.Entries = append(p.Entries, e)
	}
	for _, pr := range o.Input.PRs {
		if !used[pr.Number] {
			return nil, fmt.Errorf("input lists PR %d, which is not a merge in the range", pr.Number)
		}
	}
	if p.Deltas.Rules, err = ruleDeltas(ctx, r, base, head); err != nil {
		return nil, err
	}
	if p.Deltas.DataFiles, err = r.nameStatus(ctx, base, head, deltaTrees...); err != nil {
		return nil, err
	}
	sort.Slice(p.Deltas.DataFiles, func(i, j int) bool { return p.Deltas.DataFiles[i].Path < p.Deltas.DataFiles[j].Path })
	if p.Deltas.Projects, err = projectDelta(ctx, r, base, head); err != nil {
		return nil, err
	}
	if p.Deltas.Readme, err = readmeDeltas(ctx, r, base, head); err != nil {
		return nil, err
	}
	summarize(p)
	content, err := canonical(p.Entries)
	if err != nil {
		return nil, err
	}
	p.ContentDigest = digest(content)
	whole, err := canonical(p)
	if err != nil {
		return nil, err
	}
	p.PacketDigest = digest(whole)
	return p, nil
}

func newTrusted(ids []int64) (trustedSet, error) {
	if len(ids) == 0 {
		return nil, errors.New("trusted user ids are required")
	}
	t := trustedSet{}
	for _, id := range ids {
		if id <= 0 {
			return nil, fmt.Errorf("trusted user id %d is not positive", id)
		}
		t[id] = true
	}
	return t, nil
}

func entryFor(ctx context.Context, r repo, m string, inputs map[int]*PRInput, used map[int]bool, trusted trustedSet) (Entry, error) {
	parents, err := r.parents(ctx, m)
	if err != nil {
		return Entry{}, err
	}
	if len(parents) != 2 {
		return Entry{}, fmt.Errorf("merge %s has %d parents, expected 2", m[:8], len(parents))
	}
	subject, err := r.subject(ctx, m)
	if err != nil {
		return Entry{}, err
	}
	head := parents[1]
	files, err := r.changedFiles(ctx, parents[0], m)
	if err != nil {
		return Entry{}, err
	}
	sort.Strings(files)
	e := Entry{MergeCommit: m, Head: head, Files: files, CI: []Check{}, Flags: []string{}}
	var pr *PRInput
	if sub := mergeSubject.FindStringSubmatch(subject); sub != nil {
		n, err := strconv.Atoi(sub[1])
		if err != nil {
			return Entry{}, fmt.Errorf("merge %s: PR number: %w", m[:8], err)
		}
		e.Number = n
		if pr = inputs[n]; pr != nil {
			used[n] = true
		}
	} else {
		e.Flags = append(e.Flags, "no PR number in the merge subject")
	}
	if pr != nil {
		e.Author, e.Ref, e.Title = quote(pr.Author), quote(pr.Ref), quote(pr.Title)
		e.CI = append(e.CI, pr.Checks...)
		sort.Slice(e.CI, func(i, j int) bool { return e.CI[i].Name < e.CI[j].Name })
		if pr.Head != head {
			e.Flags = append(e.Flags, "input head differs from the merged head")
		}
	} else {
		e.Flags = append(e.Flags, "no pull request input")
	}
	e.Class, e.ClassReason = classify(pr, files, readmeOutside(ctx, r, parents[0], m, files))
	if e.Class == ClassData {
		date, err := r.committerDate(ctx, head)
		if err != nil {
			return Entry{}, fmt.Errorf("committer date of %s: %w", head[:8], err)
		}
		e.Gate, e.Review = checkGate(pr, head, date, trusted), checkReview(pr, head, date, trusted)
	} else {
		e.Gate, e.Review = Marker{Status: NotChecked}, Marker{Status: NotChecked}
	}
	return e, nil
}

func summarize(p *Packet) {
	s := &p.Summary
	s.DirectCommits = len(p.DirectCommits)
	for _, e := range p.Entries {
		switch e.Class {
		case ClassData:
			s.DataPRs++
			if e.Gate.Status == Verified && e.Review.Status == Verified {
				s.Verified++
			} else {
				s.Unverified++
			}
		case ClassNonData:
			s.NonData++
		case ClassTrustPath:
			s.TrustPath++
		}
	}
	for _, d := range p.Deltas.Readme {
		if d.Decrease {
			s.Decreases++
		}
	}
}
