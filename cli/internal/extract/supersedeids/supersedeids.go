// SPDX-License-Identifier: AGPL-3.0-only

// Package supersedeids names, for tests only, the rules the served-API
// supersede changes in the shipped rule pack: the 25 reviewed Kubernetes
// API-removal rules and the 29 mechanical rules that replace them. The shipped
// pack holds one generation or the other. Tests that name a rule of the pack
// use ID so that they pass before and after the data change. The package is a
// leaf (it imports nothing of this module) so that any package's tests can use
// it. No production code imports it.
package supersedeids

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// MechanicalPrefix is the id prefix of the mechanical Kubernetes rules.
const MechanicalPrefix = "kubernetes.served-api-removal."

// replacements maps the id of each reviewed rule to the id of the mechanical
// rule that replaces it.
var replacements = map[string]string{
	"kubernetes.admissionwebhook-v1beta1-removed.1-21-0-to-1-22-0":    "kubernetes.served-api-removal.admissionregistration-k8s-io-v1beta1.1-21-0-to-1-22-0",
	"kubernetes.apiservice-v1beta1-removed.1-21-0-to-1-22-0":          "kubernetes.served-api-removal.apiregistration-k8s-io-v1beta1.1-21-0-to-1-22-0",
	"kubernetes.crd-v1beta1-removed.1-21-0-to-1-22-0":                 "kubernetes.served-api-removal.apiextensions-k8s-io-v1beta1.1-21-0-to-1-22-0",
	"kubernetes.cronjob-v1beta1-removed.1-24-0-to-1-25-0":             "kubernetes.served-api-removal.batch-v1beta1.1-24-0-to-1-25-0",
	"kubernetes.csistoragecapacity-v1beta1-removed.1-26-0-to-1-27-0":  "kubernetes.served-api-removal.storage-k8s-io-v1beta1.1-26-0-to-1-27-0",
	"kubernetes.csr-v1beta1-removed.1-21-0-to-1-22-0":                 "kubernetes.served-api-removal.certificates-k8s-io-v1beta1.1-21-0-to-1-22-0",
	"kubernetes.endpointslice-v1beta1-removed.1-24-0-to-1-25-0":       "kubernetes.served-api-removal.discovery-k8s-io-v1beta1.1-24-0-to-1-25-0",
	"kubernetes.event-v1beta1-removed.1-24-0-to-1-25-0":               "kubernetes.served-api-removal.events-k8s-io-v1beta1.1-24-0-to-1-25-0",
	"kubernetes.flowcontrol-v1beta1-removed.1-25-0-to-1-26-0":         "kubernetes.served-api-removal.flowcontrol-apiserver-k8s-io-v1beta1.1-25-0-to-1-26-0",
	"kubernetes.flowcontrol-v1beta2-removed.1-28-0-to-1-29-0":         "kubernetes.served-api-removal.flowcontrol-apiserver-k8s-io-v1beta2.1-28-0-to-1-29-0",
	"kubernetes.flowcontrol-v1beta3-removed.1-31-0-to-1-32-0":         "kubernetes.served-api-removal.flowcontrol-apiserver-k8s-io-v1beta3.1-31-0-to-1-32-0",
	"kubernetes.hpa-v2beta1-removed.1-24-0-to-1-25-0":                 "kubernetes.served-api-removal.autoscaling-v2beta1.1-24-0-to-1-25-0",
	"kubernetes.hpa-v2beta2-removed.1-25-0-to-1-26-0":                 "kubernetes.served-api-removal.autoscaling-v2beta2.1-25-0-to-1-26-0",
	"kubernetes.ingress-extensions-v1beta1-removed.1-21-0-to-1-22-0":  "kubernetes.served-api-removal.extensions-v1beta1.1-21-0-to-1-22-0",
	"kubernetes.ingress-networking-v1beta1-removed.1-21-0-to-1-22-0":  "kubernetes.served-api-removal.networking-k8s-io-v1beta1-ingress.1-21-0-to-1-22-0",
	"kubernetes.ingressclass-v1beta1-removed.1-21-0-to-1-22-0":        "kubernetes.served-api-removal.networking-k8s-io-v1beta1-ingressclass.1-21-0-to-1-22-0",
	"kubernetes.lease-v1beta1-removed.1-21-0-to-1-22-0":               "kubernetes.served-api-removal.coordination-k8s-io-v1beta1.1-21-0-to-1-22-0",
	"kubernetes.pdb-v1beta1-removed.1-24-0-to-1-25-0":                 "kubernetes.served-api-removal.policy-v1beta1-pdb.1-24-0-to-1-25-0",
	"kubernetes.priorityclass-v1beta1-removed.1-21-0-to-1-22-0":       "kubernetes.served-api-removal.scheduling-k8s-io-v1beta1.1-21-0-to-1-22-0",
	"kubernetes.psp-v1beta1-removed.1-24-0-to-1-25-0":                 "kubernetes.served-api-removal.policy-v1beta1-psp.1-24-0-to-1-25-0",
	"kubernetes.rbac-v1beta1-removed.1-21-0-to-1-22-0":                "kubernetes.served-api-removal.rbac-authorization-k8s-io-v1beta1.1-21-0-to-1-22-0",
	"kubernetes.runtimeclass-v1beta1-removed.1-24-0-to-1-25-0":        "kubernetes.served-api-removal.node-k8s-io-v1beta1.1-24-0-to-1-25-0",
	"kubernetes.storage-v1beta1-removed.1-21-0-to-1-22-0":             "kubernetes.served-api-removal.storage-k8s-io-v1beta1.1-21-0-to-1-22-0",
	"kubernetes.subjectaccessreview-v1beta1-removed.1-21-0-to-1-22-0": "kubernetes.served-api-removal.authorization-k8s-io-v1beta1.1-21-0-to-1-22-0",
	"kubernetes.tokenreview-v1beta1-removed.1-21-0-to-1-22-0":         "kubernetes.served-api-removal.authentication-k8s-io-v1beta1.1-21-0-to-1-22-0",
}

// addedIDs are the mechanical rules with no reviewed predecessor: the
// removals of 1.33, 1.34 and 1.37 that the reviewed pack never covered.
var addedIDs = []string{
	"kubernetes.served-api-removal.admissionregistration-k8s-io-v1beta1.1-33-0-to-1-34-0",
	"kubernetes.served-api-removal.authentication-k8s-io-v1beta1.1-32-0-to-1-33-0",
	"kubernetes.served-api-removal.networking-k8s-io-v1beta1.1-36-0-to-1-37-0",
	"kubernetes.served-api-removal.storage-k8s-io-v1beta1.1-36-0-to-1-37-0",
}

// ReviewedIDs returns the ids of the 25 reviewed rules.
func ReviewedIDs() []string {
	out := make([]string, 0, len(replacements))
	for id := range replacements {
		out = append(out, id)
	}
	return out
}

// AddedIDs returns the ids of the mechanical rules with no reviewed
// predecessor.
func AddedIDs() []string { return append([]string(nil), addedIDs...) }

// ReplacementIDs returns the mechanical id of each reviewed id.
func ReplacementIDs() map[string]string {
	out := make(map[string]string, len(replacements))
	for k, v := range replacements {
		out[k] = v
	}
	return out
}

var (
	generationOnce sync.Once
	generation     bool
	generationErr  error
)

// Superseded reports whether the shipped rule pack (cncfcheck/data/rules.json,
// read from this source tree) holds the mechanical Kubernetes rules. It panics
// when the pack holds a mix of the two generations: that is a data error, not
// a state a test can be written for.
func Superseded() bool {
	generationOnce.Do(func() {
		raw, err := shippedPack()
		if err != nil {
			generationErr = err
			return
		}
		generation, generationErr = Generation(raw)
	})
	if generationErr != nil {
		panic("supersedeids: " + generationErr.Error())
	}
	return generation
}

// Generation reports whether pack holds the mechanical Kubernetes rules (true)
// or the reviewed ones (false). A pack holding some of both, or only part of
// either, is an error.
func Generation(pack []byte) (bool, error) {
	var p struct {
		Entries []struct {
			Rule struct {
				ID string `json:"id"`
			} `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(pack, &p); err != nil {
		return false, err
	}
	reviewed, mechanical := 0, 0
	for _, entry := range p.Entries {
		id := entry.Rule.ID
		if _, ok := replacements[id]; ok {
			reviewed++
		}
		if strings.HasPrefix(id, MechanicalPrefix) {
			mechanical++
		}
	}
	switch {
	case reviewed == len(replacements) && mechanical == 0:
		return false, nil
	case reviewed == 0 && mechanical == len(replacements)+len(addedIDs):
		return true, nil
	}
	return false, fmt.Errorf("the pack holds %d reviewed and %d mechanical Kubernetes API-removal rules, want 25/0 or 0/29", reviewed, mechanical)
}

// ID returns the id a test must use for the rule the reviewed id names: the
// reviewed id itself while the shipped pack holds the reviewed rules, the id
// of its mechanical replacement afterwards.
func ID(reviewed string) string {
	if !Superseded() {
		return reviewed
	}
	if id, ok := replacements[reviewed]; ok {
		return id
	}
	panic("supersedeids: not a reviewed Kubernetes rule id: " + reviewed)
}

// AgeWindowDays is how many days before the earliest expiry of the shipped
// pack the shared test clock is placed: inside the 30-day window in which the
// knowledge-age note appears, with room on both sides.
const AgeWindowDays = 17

// Clock is the one instant the tests that need "now" for the shipped pack use.
// It is derived from the pack, never written down, so a data-only change of
// the pack (the supersede, a renewal) moves it by itself:
//
//   - it is AgeWindowDays before the day of the earliest validUntil of any
//     active rule (inside the age window of the earliest expiry), and
//   - never earlier than the day after the latest reviewedAt of a Kubernetes
//     API-removal rule of either generation (a mechanical rule is reviewed
//     when it is derived, and its evidence clock must not be before that).
//
// It panics when that instant is not before the earliest validUntil of every
// active rule (Kubernetes API-removal or not): then no clock holds all of them
// current and the pack needs its other rules renewed first.
func Clock() time.Time {
	loadClocks()
	if clockErr != nil {
		panic("supersedeids: " + clockErr.Error())
	}
	return clock
}

// AgeClocks returns the instants before, inside and after the age window of
// the earliest expiry of the shipped pack: 31 days and 17 days before, and 3
// days after, the day of the earliest validUntil of any active rule. They depend on the
// other rules' leases only, not on when the Kubernetes rules were derived.
func AgeClocks() (before, inside, after time.Time) {
	loadClocks()
	if clockErr != nil {
		panic("supersedeids: " + clockErr.Error())
	}
	return ageBefore, ageInside, ageAfter
}

var (
	clockOnce                      sync.Once
	clock                          time.Time
	ageBefore, ageInside, ageAfter time.Time
	clockErr                       error
)

func loadClocks() {
	clockOnce.Do(func() {
		raw, err := shippedPack()
		if err != nil {
			clockErr = err
			return
		}
		var c Clocks
		if c, clockErr = ClocksOf(raw); clockErr == nil {
			clock, ageBefore, ageInside, ageAfter = c.Clock, c.Before, c.Inside, c.After
		}
	})
}

// Window is the evidence window of a synthetic rule that is current at Clock:
// reviewed the given number of days before it and valid until the given number
// of days after it (RFC 3339, midnight UTC). The shipped lease is at most 90
// days, so before+after must not exceed that.
func Window(before, after int) (reviewedAt, validUntil string) {
	at := Clock()
	return at.AddDate(0, 0, -before).Format(time.RFC3339), at.AddDate(0, 0, after).Format(time.RFC3339)
}

// ClockString is Clock in RFC 3339 form, as the --now flags take it.
func ClockString() string { return Clock().Format(time.RFC3339) }

// Clocks are the instants derived from a pack.
type Clocks struct {
	// Clock is the shared test clock (see Clock).
	Clock time.Time
	// Before, Inside and After are the age instants (see AgeClocks).
	Before, Inside, After time.Time
}

// ClockOf derives the shared test clock from the bytes of a rule pack. See
// Clock for the rule.
func ClockOf(pack []byte) (time.Time, error) {
	c, err := ClocksOf(pack)
	return c.Clock, err
}

// ClocksOf derives the shared test clock and the age instants from the bytes
// of a rule pack.
func ClocksOf(pack []byte) (Clocks, error) {
	var p struct {
		Entries []struct {
			Rule struct {
				ID       string `json:"id"`
				Evidence struct {
					State      string `json:"state"`
					ReviewedAt string `json:"reviewedAt"`
					ValidUntil string `json:"validUntil"`
				} `json:"evidence"`
			} `json:"rule"`
		} `json:"entries"`
	}
	if err := json.Unmarshal(pack, &p); err != nil {
		return Clocks{}, err
	}
	var earliest, lastReviewed, kubernetesUntil time.Time
	for _, entry := range p.Entries {
		ev := entry.Rule.Evidence
		if ev.State != "" && ev.State != "active" {
			continue
		}
		until, err := time.Parse(time.RFC3339, ev.ValidUntil)
		if err != nil {
			return Clocks{}, fmt.Errorf("rule %s: validUntil: %v", entry.Rule.ID, err)
		}
		if earliest.IsZero() || until.Before(earliest) {
			earliest = until
		}
		if !isAPIRemoval(entry.Rule.ID) {
			continue
		}
		reviewed, err := time.Parse(time.RFC3339, ev.ReviewedAt)
		if err != nil {
			return Clocks{}, fmt.Errorf("rule %s: reviewedAt: %v", entry.Rule.ID, err)
		}
		if reviewed.After(lastReviewed) {
			lastReviewed = reviewed
		}
		if kubernetesUntil.IsZero() || until.Before(kubernetesUntil) {
			kubernetesUntil = until
		}
	}
	if earliest.IsZero() {
		return Clocks{}, fmt.Errorf("the pack holds no active rule")
	}
	inside := earliest.UTC().Truncate(24*time.Hour).AddDate(0, 0, -AgeWindowDays)
	c := Clocks{Clock: inside, Before: inside.AddDate(0, 0, -14), Inside: inside, After: inside.AddDate(0, 0, 20)}
	if !lastReviewed.IsZero() {
		if after := lastReviewed.UTC().Truncate(24*time.Hour).AddDate(0, 0, 1); c.Clock.Before(after) {
			c.Clock = after
		}
		if !c.Clock.Before(kubernetesUntil) {
			return Clocks{}, fmt.Errorf("no clock holds every Kubernetes rule current: %s is not before the earliest Kubernetes expiry %s", c.Clock.Format(time.RFC3339), kubernetesUntil.Format(time.RFC3339))
		}
		if !c.Clock.Before(earliest) {
			return Clocks{}, fmt.Errorf("no clock holds every rule current: %s (after the last Kubernetes review) is not before the earliest expiry of all rules %s (renew the other rules first)", c.Clock.Format(time.RFC3339), earliest.Format(time.RFC3339))
		}
	}
	return c, nil
}

// isAPIRemoval reports whether id is a Kubernetes API-removal rule of either
// generation.
func isAPIRemoval(id string) bool {
	_, reviewed := replacements[id]
	return reviewed || strings.HasPrefix(id, MechanicalPrefix)
}

func shippedPack() ([]byte, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("cannot locate the source tree")
	}
	return os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "cncfcheck", "data", "rules.json"))
}
