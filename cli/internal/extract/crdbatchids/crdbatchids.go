// SPDX-License-Identifier: AGPL-3.0-only

// Package crdbatchids names, for tests only, the second batch of mechanical
// custom-resource version-removal rules (crd.version-removal extractors) and
// the line attestations that come with it: 13 rules for Crossplane, Kyverno
// and Strimzi, and five quiet Strimzi lines. The shipped pack holds
// the whole batch or none of it, and no other custom-resource version-removal
// rule. Tests whose expectations depend on the batch (rule counts, claim
// counts, route outcomes) state both cases through this package, so that they
// pass before and after the data change and stay exact in each. The package
// is a leaf (it imports nothing of this module) so that any package's tests
// can use it. No production code imports it.
package crdbatchids

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
)

// Marker is the part of every custom-resource version-removal rule id that
// names the rule kind.
const Marker = ".crd-version-removal."

// FactFamily is the line attestation family of the batch.
const FactFamily = "crd.custom_resource_versions"

// Rule is one rule of the batch as the batch states it: a forbid_set_member
// rule over the project's custom-resource version set on the proposed side.
type Rule struct {
	ID        string
	Project   string
	Component string
	From, To  string
	Members   []string
}

// FactID is the set fact the rule reads.
func (r Rule) FactID() string {
	return "component." + r.Project + ".custom_resource_versions_set"
}

var rules = []Rule{
	{"crossplane.crd-version-removal.compositionrevisions-apiextensions-crossplane-io.1-20-0-to-2-0-0", "crossplane", "pkg:github/crossplane/crossplane", "1.20.0", "2.0.0", []string{"apiextensions.crossplane.io/v1beta1/CompositionRevision"}},
	{"crossplane.crd-version-removal.environmentconfigs-apiextensions-crossplane-io.1-20-0-to-2-0-0", "crossplane", "pkg:github/crossplane/crossplane", "1.20.0", "2.0.0", []string{"apiextensions.crossplane.io/v1alpha1/EnvironmentConfig"}},
	{"kyverno.crd-version-removal.updaterequests-kyverno-io.1-15-0-to-1-16-0", "kyverno", "pkg:github/kyverno/kyverno", "1.15.0", "1.16.0", []string{"kyverno.io/v1beta1/UpdateRequest"}},
	{"strimzi.crd-version-removal.kafkabridges-kafka-strimzi-io.0-51-0-to-1-0-0", "strimzi", "pkg:github/strimzi/strimzi-kafka-operator", "0.51.0", "1.0.0", []string{"kafka.strimzi.io/v1beta2/KafkaBridge"}},
	{"strimzi.crd-version-removal.kafkaconnectors-kafka-strimzi-io.0-51-0-to-1-0-0", "strimzi", "pkg:github/strimzi/strimzi-kafka-operator", "0.51.0", "1.0.0", []string{"kafka.strimzi.io/v1beta2/KafkaConnector"}},
	{"strimzi.crd-version-removal.kafkaconnects-kafka-strimzi-io.0-51-0-to-1-0-0", "strimzi", "pkg:github/strimzi/strimzi-kafka-operator", "0.51.0", "1.0.0", []string{"kafka.strimzi.io/v1beta2/KafkaConnect"}},
	{"strimzi.crd-version-removal.kafkamirrormaker2s-kafka-strimzi-io.0-51-0-to-1-0-0", "strimzi", "pkg:github/strimzi/strimzi-kafka-operator", "0.51.0", "1.0.0", []string{"kafka.strimzi.io/v1beta2/KafkaMirrorMaker2"}},
	{"strimzi.crd-version-removal.kafkanodepools-kafka-strimzi-io.0-51-0-to-1-0-0", "strimzi", "pkg:github/strimzi/strimzi-kafka-operator", "0.51.0", "1.0.0", []string{"kafka.strimzi.io/v1beta2/KafkaNodePool"}},
	{"strimzi.crd-version-removal.kafkarebalances-kafka-strimzi-io.0-51-0-to-1-0-0", "strimzi", "pkg:github/strimzi/strimzi-kafka-operator", "0.51.0", "1.0.0", []string{"kafka.strimzi.io/v1beta2/KafkaRebalance"}},
	{"strimzi.crd-version-removal.kafkas-kafka-strimzi-io.0-51-0-to-1-0-0", "strimzi", "pkg:github/strimzi/strimzi-kafka-operator", "0.51.0", "1.0.0", []string{"kafka.strimzi.io/v1beta2/Kafka"}},
	{"strimzi.crd-version-removal.kafkatopics-kafka-strimzi-io.0-51-0-to-1-0-0", "strimzi", "pkg:github/strimzi/strimzi-kafka-operator", "0.51.0", "1.0.0", []string{"kafka.strimzi.io/v1alpha1/KafkaTopic", "kafka.strimzi.io/v1beta1/KafkaTopic", "kafka.strimzi.io/v1beta2/KafkaTopic"}},
	{"strimzi.crd-version-removal.kafkausers-kafka-strimzi-io.0-51-0-to-1-0-0", "strimzi", "pkg:github/strimzi/strimzi-kafka-operator", "0.51.0", "1.0.0", []string{"kafka.strimzi.io/v1alpha1/KafkaUser", "kafka.strimzi.io/v1beta1/KafkaUser", "kafka.strimzi.io/v1beta2/KafkaUser"}},
	{"strimzi.crd-version-removal.strimzipodsets-core-strimzi-io.0-51-0-to-1-0-0", "strimzi", "pkg:github/strimzi/strimzi-kafka-operator", "0.51.0", "1.0.0", []string{"core.strimzi.io/v1beta2/StrimziPodSet"}},
}

// Line is one line attestation of the batch: a quiet line (no rule) of the
// custom-resource version family.
type Line struct {
	Component string
	Line      string
}

var lines = []Line{
	{"pkg:github/strimzi/strimzi-kafka-operator", "0.50"},
	{"pkg:github/strimzi/strimzi-kafka-operator", "0.51"},
	{"pkg:github/strimzi/strimzi-kafka-operator", "1.1"},
	{"pkg:github/strimzi/strimzi-kafka-operator", "1.2"},
	{"pkg:github/strimzi/strimzi-kafka-operator", "1.3"},
}

// otherQuiet are quiet lines of the same family that other changes ship (the
// keda, cert-manager and velero targets). Holds accepts them; they are
// not part of the all-or-none batch and are not counted.
var otherQuiet = []Line{
	{"pkg:github/cert-manager/cert-manager", "1.20"},
	{"pkg:github/cert-manager/cert-manager", "1.21"},
	{"pkg:github/kedacore/keda", "2.17"},
	{"pkg:github/kedacore/keda", "2.18"},
	{"pkg:github/kedacore/keda", "2.19"},
	{"pkg:github/kedacore/keda", "2.20"},
	{"pkg:github/kedacore/keda", "2.21"},
	{"pkg:github/velero-io/velero", "1.14"},
	{"pkg:github/velero-io/velero", "1.15"},
	{"pkg:github/velero-io/velero", "1.16"},
	{"pkg:github/velero-io/velero", "1.17"},
	{"pkg:github/velero-io/velero", "1.18"},
}

// Rules returns the batch's rules in id order.
func Rules() []Rule {
	out := make([]Rule, len(rules))
	for i, r := range rules {
		r.Members = append([]string(nil), r.Members...)
		out[i] = r
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// IDs returns the batch's rule ids in ascending order.
func IDs() []string {
	ids := make([]string, 0, len(rules))
	for _, r := range rules {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	return ids
}

// ProjectRules returns the batch's rules of one project, in id order.
func ProjectRules(project string) []Rule {
	var out []Rule
	for _, r := range Rules() {
		if r.Project == project {
			out = append(out, r)
		}
	}
	return out
}

// Lines returns the batch's line attestations.
func Lines() []Line { return append([]Line(nil), lines...) }

// ShippedLines returns every quiet custom-resource-family line attestation
// the shipped pack carries once the batch is shipped (the batch's and the other
// shipped quiet lines), ordered as the pack orders them; none before.
func ShippedLines() []Line {
	if !Shipped() {
		return nil
	}
	out := append(Lines(), otherQuiet...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Component != out[j].Component {
			return out[i].Component < out[j].Component
		}
		return out[i].Line < out[j].Line
	})
	return out
}

var (
	shippedOnce sync.Once
	shipped     bool
	shippedErr  error
)

// Shipped reports whether the shipped rule pack (cncfcheck/data/rules.json,
// read from this source tree) holds the batch. It panics when the pack holds
// part of it, a rule that differs from the batch's statement, or another
// custom-resource version-removal rule: that is a data error, not a state a
// test can be written for.
func Shipped() bool {
	shippedOnce.Do(func() {
		raw, err := shippedPack()
		if err != nil {
			shippedErr = err
			return
		}
		shipped, shippedErr = Holds(raw)
	})
	if shippedErr != nil {
		panic("crdbatchids: " + shippedErr.Error())
	}
	return shipped
}

// Count is the number of the batch's rules of project the shipped pack
// holds: all of them once the batch is shipped, none before.
func Count(project string) int {
	if !Shipped() {
		return 0
	}
	return len(ProjectRules(project))
}

// subject is a rule's subject: component and release pair.
type subject struct {
	Component string `json:"component"`
	From      string `json:"from"`
	To        string `json:"to"`
}

// Holds reports whether pack holds the batch (true) or none of it (false).
// A pack holding part of the batch, a batch rule that differs from its
// statement here (project, operator, subject, set condition), a line
// attestation of the family that is neither a quiet line of the batch nor
// one of the other shipped quiet lines, or any
// other custom-resource version-removal rule is an error.
func Holds(pack []byte) (bool, error) {
	var p struct {
		Entries []struct {
			Project string `json:"project"`
			Rule    struct {
				ID           string  `json:"id"`
				Operator     string  `json:"operator"`
				Subject      subject `json:"subject"`
				SetCondition *struct {
					Side      string   `json:"side"`
					Component string   `json:"component"`
					FactID    string   `json:"factId"`
					Members   []string `json:"members"`
				} `json:"setCondition"`
			} `json:"rule"`
		} `json:"entries"`
		LineAttestations []struct {
			Component  string    `json:"component"`
			Line       string    `json:"line"`
			FactFamily string    `json:"factFamily"`
			RuleIDs    *[]string `json:"ruleIds"`
		} `json:"lineAttestations"`
	}
	if err := json.Unmarshal(pack, &p); err != nil {
		return false, err
	}
	byID := map[string]Rule{}
	for _, r := range rules {
		byID[r.ID] = r
	}
	held := 0
	for _, entry := range p.Entries {
		got := entry.Rule
		want, ok := byID[got.ID]
		if !ok {
			if strings.Contains(got.ID, Marker) {
				return false, fmt.Errorf("the pack holds custom-resource version-removal rule %s, which is not of the batch", got.ID)
			}
			continue
		}
		held++
		set := got.SetCondition
		// The subject is compared as a whole: this is the batch's statement
		// of its rule, not transition matching.
		if entry.Project != want.Project || got.Operator != "forbid_set_member" || got.Subject != (subject{want.Component, want.From, want.To}) ||
			set == nil || set.Side != "proposed" || set.Component != want.Component || set.FactID != want.FactID() || strings.Join(set.Members, "\n") != strings.Join(want.Members, "\n") {
			return false, fmt.Errorf("the pack's rule %s differs from the batch's statement of it", got.ID)
		}
	}
	attested := 0
	seen := map[Line]bool{}
	for _, a := range p.LineAttestations {
		if a.FactFamily != FactFamily {
			continue
		}
		if l := (Line{a.Component, a.Line}); seen[l] {
			return false, fmt.Errorf("the pack's %s line attestation %s %s is repeated", FactFamily, a.Component, a.Line)
		} else {
			seen[l] = true
		}
		known, inBatch := false, false
		for _, l := range lines {
			if l.Component == a.Component && l.Line == a.Line {
				known, inBatch = true, true
			}
		}
		for _, l := range otherQuiet {
			if l.Component == a.Component && l.Line == a.Line {
				known = true
			}
		}
		if !known || a.RuleIDs == nil || len(*a.RuleIDs) != 0 {
			return false, fmt.Errorf("the pack's %s line attestation %s %s is not a quiet line of the batch", FactFamily, a.Component, a.Line)
		}
		if inBatch {
			attested++
		}
	}
	switch {
	case held == 0 && attested == 0:
		return false, nil
	case held == len(rules) && attested == len(lines):
		return true, nil
	}
	return false, fmt.Errorf("the pack holds %d of the batch's %d rules and %d of its %d line attestations, want all or none", held, len(rules), attested, len(lines))
}

func shippedPack() ([]byte, error) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return nil, fmt.Errorf("cannot locate the source tree")
	}
	return os.ReadFile(filepath.Join(filepath.Dir(file), "..", "..", "cncfcheck", "data", "rules.json"))
}
