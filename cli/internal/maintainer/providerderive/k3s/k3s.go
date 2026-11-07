// SPDX-License-Identifier: AGPL-3.0-only

// Package k3s derives k3s version -> upstream Kubernetes version rows from
// committed release excerpts of github.com/k3s-io/k3s.
//
// Rules: only final tags vX.Y.Z+k3sN map; rc/alpha/beta (and any other
// suffix) are Unknown; the Kubernetes version comes only from the body
// sentence of a GA release and must equal the tag's version; a GA body
// without the sentence is Unknown; API order is irrelevant (output is
// sorted by parsed version).
package k3s

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/providerderive"
)

const (
	Provider     = "k3s"
	Distribution = "k3s"
	Repo         = "k3s-io/k3s"
)

var (
	finalRE = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\+k3s([1-9][0-9]*)$`)
	// A valid core followed by a pre-release identifier, then the build.
	preRE      = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-([0-9A-Za-z.]+)\+k3s[1-9][0-9]*$`)
	prekindRE  = regexp.MustCompile(`^(rc|alpha|beta)[0-9]*$`)
	sentenceRE = regexp.MustCompile(`^This release updates Kubernetes to (v(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)), and fixes a number of issues\.$`)
)

const sentencePrefix = "This release updates Kubernetes to"

// Derive maps every excerpt. Any drift aborts with no output.
func Derive(in []providerderive.Input) (providerderive.Result, error) {
	if err := providerderive.CheckDistinctIDs(Provider, in); err != nil {
		return providerderive.Result{}, err
	}
	rows := []providerderive.Row{}
	unk := []providerderive.Unknown{}
	for _, i := range in {
		id := i.Entry.ID
		h, body, err := providerderive.Open(Provider, Repo, i)
		if err != nil {
			return providerderive.Result{}, err
		}
		if m := finalRE.FindStringSubmatch(h.Tag); m != nil {
			if h.Prerelease || h.Draft {
				unk = append(unk, providerderive.Unknown{Excerpt: id, Tag: h.Tag, Reason: providerderive.ReasonFlagged})
				continue
			}
			core := "v" + m[1] + "." + m[2] + "." + m[3]
			k8s, found, err := sentence(id, body)
			if err != nil {
				return providerderive.Result{}, err
			}
			if !found {
				unk = append(unk, providerderive.Unknown{Excerpt: id, Tag: h.Tag, Reason: providerderive.ReasonNoMapping})
				continue
			}
			if k8s != core {
				return providerderive.Result{}, providerderive.Drift(Provider, id, "body Kubernetes version %s differs from tag %s", k8s, h.Tag)
			}
			rows = append(rows, providerderive.Row{
				Distribution: Distribution, ProviderVersion: h.Tag, Kubernetes: k8s,
				Excerpt: id, ExcerptSHA256: i.Entry.SHA256,
			})
			continue
		}
		if m := preRE.FindStringSubmatch(h.Tag); m != nil {
			reason := providerderive.ReasonUnknownSuffix
			if prekindRE.MatchString(m[4]) {
				reason = providerderive.ReasonPrerelease
			}
			unk = append(unk, providerderive.Unknown{Excerpt: id, Tag: h.Tag, Reason: reason})
			continue
		}
		return providerderive.Result{}, providerderive.Drift(Provider, id, "tag %q is not in the k3s tag grammar", h.Tag)
	}
	rows, err := providerderive.Merge(Provider, rows, less)
	if err != nil {
		return providerderive.Result{}, err
	}
	providerderive.SortUnknown(unk)
	return providerderive.Result{Rows: rows, Unknown: unk}, nil
}

// sentence finds the single mapping sentence. A line that starts like it but
// does not match exactly, or a second one, is drift.
func sentence(id string, body []string) (string, bool, error) {
	var got string
	n := 0
	for _, l := range body {
		if !strings.HasPrefix(l, sentencePrefix) {
			continue
		}
		m := sentenceRE.FindStringSubmatch(l)
		if m == nil {
			return "", false, providerderive.Drift(Provider, id, "unparsable Kubernetes version sentence")
		}
		got = m[1]
		n++
	}
	if n > 1 {
		return "", false, providerderive.Drift(Provider, id, "more than one Kubernetes version sentence")
	}
	return got, n == 1, nil
}

func key(tag string) [4]int {
	m := finalRE.FindStringSubmatch(tag)
	var k [4]int
	for i := 0; i < 4; i++ {
		k[i], _ = strconv.Atoi(m[i+1])
	}
	return k
}

func less(a, b providerderive.Row) bool {
	x, y := key(a.ProviderVersion), key(b.ProviderVersion)
	for i := range x {
		if x[i] != y[i] {
			return x[i] < y[i]
		}
	}
	return false
}
