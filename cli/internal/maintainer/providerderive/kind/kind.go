// SPDX-License-Identifier: AGPL-3.0-only

// Package kind derives kind version -> default Kubernetes version rows from
// committed release excerpts of github.com/kubernetes-sigs/kind. kind is a
// developer tool: every row is marked NonProduction and must never be shown
// as production fidelity.
//
// Rules: only final tags vX.Y.Z map; alpha/beta/rc (and any other suffix) are
// Unknown; releases before v0.27.0 state no mapping and are Unknown, never
// guessed; the version comes only from the default node image sentence
// (digest mandatory), cross-checked against the pre-built image list when
// that is present; API order is irrelevant.
package kind

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/maintainer/providerderive"
)

const (
	Provider     = "kind"
	Distribution = "kind"
	Repo         = "kubernetes-sigs/kind"
)

var (
	finalRE   = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	preRE     = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-([0-9A-Za-z.]+)$`)
	prekindRE = regexp.MustCompile(`^(rc|alpha|beta)[0-9.]*$`)

	defaultRE = regexp.MustCompile("^The default node image is now +`(kindest/node:(v(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*))@sha256:([0-9a-f]{64}))`$")
	bulletRE  = regexp.MustCompile("^[*-] (v(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)): `(kindest/node:(v(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*)\\.(?:0|[1-9][0-9]*))@sha256:([0-9a-f]{64}))`$")
	// Anything that looks like a list item but is not a * or - bullet.
	oddBulletRE = regexp.MustCompile(`^\s*([*+-]|[0-9]+[.)])\s`)
)

const (
	defaultPrefix = "The default node image is now"
	listHeading   = "Images pre-built for this release:"
	// FirstMapped is the first kind release whose body states a mapping.
	firstMinor = 27
)

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
			if before(m) {
				unk = append(unk, providerderive.Unknown{Excerpt: id, Tag: h.Tag, Reason: providerderive.ReasonBeforeFirstKind})
				continue
			}
			k8s, image, found, err := mapping(id, body)
			if err != nil {
				return providerderive.Result{}, err
			}
			if !found {
				unk = append(unk, providerderive.Unknown{Excerpt: id, Tag: h.Tag, Reason: providerderive.ReasonNoMapping})
				continue
			}
			rows = append(rows, providerderive.Row{
				Distribution: Distribution, ProviderVersion: h.Tag, Kubernetes: k8s, NodeImage: image,
				NonProduction: true, Excerpt: id, ExcerptSHA256: i.Entry.SHA256,
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
		return providerderive.Result{}, providerderive.Drift(Provider, id, "tag %q is not in the kind tag grammar", h.Tag)
	}
	rows, err := providerderive.Merge(Provider, rows, less)
	if err != nil {
		return providerderive.Result{}, err
	}
	providerderive.SortUnknown(unk)
	return providerderive.Result{Rows: rows, Unknown: unk}, nil
}

// before reports whether the release (major, minor submatches) is older than
// v0.27.0.
func before(m []string) bool {
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	return maj == 0 && min < firstMinor
}

// mapping reads the single default image sentence and cross-checks the image
// list. Returns found=false when the body states neither.
func mapping(id string, body []string) (k8s, image string, found bool, err error) {
	var digest string
	n := 0
	for _, l := range body {
		if !strings.HasPrefix(l, defaultPrefix) {
			continue
		}
		m := defaultRE.FindStringSubmatch(l)
		if m == nil {
			return "", "", false, providerderive.Drift(Provider, id, "unparsable default node image sentence")
		}
		image, k8s, digest = m[1], m[2], m[3]
		n++
	}
	if n > 1 {
		return "", "", false, providerderive.Drift(Provider, id, "more than one default node image sentence")
	}
	list, err := imageList(id, body)
	if err != nil {
		return "", "", false, err
	}
	if n == 0 {
		return "", "", false, nil
	}
	if want, ok := list[k8s]; ok && want != digest {
		return "", "", false, providerderive.Drift(Provider, id, "default image digest differs from the pre-built list for %s", k8s)
	}
	return k8s, image, true, nil
}

// imageList parses the bullets after the heading (if any) into version ->
// digest. A label that differs from its image tag, a duplicate version or a
// bullet in another style is drift.
func imageList(id string, body []string) (map[string]string, error) {
	out := map[string]string{}
	heading := -1
	for i, l := range body {
		if l == listHeading {
			if heading >= 0 {
				return nil, providerderive.Drift(Provider, id, "more than one pre-built image list")
			}
			heading = i
		}
	}
	if heading < 0 {
		return out, nil
	}
	j := heading + 1
	for j < len(body) && strings.TrimSpace(body[j]) == "" {
		j++
	}
	for ; j < len(body) && oddBulletRE.MatchString(body[j]); j++ {
		m := bulletRE.FindStringSubmatch(body[j])
		if m == nil {
			return nil, providerderive.Drift(Provider, id, "unparsable pre-built image bullet")
		}
		if m[1] != m[3] {
			return nil, providerderive.Drift(Provider, id, "image label %s differs from image tag %s", m[1], m[3])
		}
		if _, dup := out[m[1]]; dup {
			return nil, providerderive.Drift(Provider, id, "duplicate pre-built image %s", m[1])
		}
		out[m[1]] = m[4]
	}
	return out, nil
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

func key(tag string) [3]int {
	m := finalRE.FindStringSubmatch(tag)
	var k [3]int
	for i := 0; i < 3; i++ {
		k[i], _ = strconv.Atoi(m[i+1])
	}
	return k
}
