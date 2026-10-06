// SPDX-License-Identifier: AGPL-3.0-only

package k8sservedapis

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"
)

type reviewedAction struct {
	ID         string `json:"id"`
	Fact       string `json:"fact"`
	NextAction string `json:"nextAction"`
}

var reviewedTarget = regexp.MustCompile(`manifest to (\S+?)(?:,| and )`)
var reviewedKinds = regexp.MustCompile(`the named (.+?) (?:resources )?manifest`)

// instructionTokens are the concrete instructions the reviewed texts carry
// besides the target version and the kinds.
var instructionTokens = []string{
	"admission", "CRDs", "stored objects", "clients", "API-server configuration",
	"reassess the complete target apply set", "Pod Security Admission", "admission webhook", "no served replacement",
}

// TestHintsCarryEveryReviewedInstruction: for all 25 reviewed rules the text
// the extractor now emits holds the target API, every kind, and every
// validation instruction of the reviewed text.
func TestHintsCarryEveryReviewedInstruction(t *testing.T) {
	raw, err := os.ReadFile("testdata/reviewed-next-actions.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []reviewedAction
	if err := json.Unmarshal(raw, &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 25 {
		t.Fatalf("%d reviewed rules, want 25", len(rows))
	}
	for _, row := range rows {
		var f *adapterFact
		for i := range adapterFacts {
			if adapterFacts[i].Fact == row.Fact {
				f = &adapterFacts[i]
			}
		}
		if f == nil {
			t.Fatalf("%s: fact %s not in the adapter table", row.ID, row.Fact)
		}
		got := migrationAction(f.Group, f.Version, f.Kinds, nil)
		low, want := strings.ToLower(got), strings.ToLower(row.NextAction)
		if m := reviewedTarget.FindStringSubmatch(row.NextAction); m != nil && !strings.Contains(got, m[1]) {
			t.Errorf("%s: target %s missing from %q", row.ID, m[1], got)
		}
		if m := reviewedKinds.FindStringSubmatch(row.NextAction); m != nil {
			for _, k := range regexp.MustCompile(`[A-Za-z]+`).FindAllString(m[1], -1) {
				if k != "or" && !strings.Contains(got, k) {
					t.Errorf("%s: kind %s missing from %q", row.ID, k, got)
				}
			}
		}
		for _, tok := range instructionTokens {
			if strings.Contains(want, strings.ToLower(tok)) && !strings.Contains(low, strings.ToLower(tok)) {
				t.Errorf("%s: %q missing from %q", row.ID, tok, got)
			}
		}
		if len(got) <= len(row.NextAction)-40 {
			t.Errorf("%s: new text is much shorter than the reviewed one", row.ID)
		}
	}
}

// TestHintsCoverEveryAdapterKind: no kind of any adapter fact falls back to the
// generic text, and the table holds nothing the adapter does not remove.
func TestHintsCoverEveryAdapterKind(t *testing.T) {
	seen := map[string]bool{}
	for _, f := range adapterFacts {
		for _, k := range f.Kinds {
			key := hintKey(f.Group, f.Version, k)
			seen[key] = true
			if _, ok := hints[key]; !ok {
				t.Errorf("no hint for %s", key)
			}
		}
		if got := migrationAction(f.Group, f.Version, f.Kinds, []string{"v9"}); strings.Contains(got, "v9") {
			t.Errorf("%s uses the derived replacement instead of the table: %s", f.Fact, got)
		}
	}
	for key := range hints {
		if !seen[key] {
			t.Errorf("hint %s has no adapter fact", key)
		}
	}
}

func TestHintSentences(t *testing.T) {
	cases := []struct {
		group, version string
		kinds          []string
		want           []string
	}{
		{"batch", "v1beta1", []string{"CronJob"}, []string{"Migrate the named CronJob manifests to batch/v1.", "Validate admission, CRDs, stored objects, runtime clients, and API-server configuration separately."}},
		{"extensions", "v1beta1", []string{"Ingress"}, []string{"networking.k8s.io/v1", "pathType is now required."}},
		{"policy", "v1beta1", []string{"PodSecurityPolicy"}, []string{"Remove PodSecurityPolicy (policy/v1beta1)", "no served replacement API", "Pod Security Admission or a 3rd party admission webhook"}},
		{"storage.k8s.io", "v1beta1", []string{"CSIDriver", "CSINode", "StorageClass", "VolumeAttachment"}, []string{"CSIDriver, CSINode, StorageClass or VolumeAttachment manifests to storage.k8s.io/v1."}},
		{"flowcontrol.apiserver.k8s.io", "v1beta1", []string{"FlowSchema", "PriorityLevelConfiguration"}, []string{"flowcontrol.apiserver.k8s.io/v1beta2 or v1beta3"}},
	}
	for _, c := range cases {
		got := migrationAction(c.group, c.version, c.kinds, nil)
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%s/%s: %q missing from %q", c.group, c.version, w, got)
			}
		}
	}
}

func TestUnknownKindFallsBackToGenericText(t *testing.T) {
	got := migrationAction("example.io", "v1beta1", []string{"Widget"}, []string{"v1"})
	if !strings.HasPrefix(got, "Migrate the named manifests to example.io/v1.") || !strings.Contains(got, "admission, CRDs") {
		t.Errorf("generic with replacement: %q", got)
	}
	got = migrationAction("example.io", "v1beta1", []string{"Widget"}, nil)
	if !strings.HasPrefix(got, "Remove the named manifests or replace them") {
		t.Errorf("generic without replacement: %q", got)
	}
	// One unknown kind makes the whole rule generic.
	if got := migrationAction("batch", "v1beta1", []string{"CronJob", "Other"}, nil); !strings.HasPrefix(got, "Remove the named manifests") {
		t.Errorf("mixed: %q", got)
	}
}

func TestMigrationActionIsDeterministic(t *testing.T) {
	for _, f := range adapterFacts {
		a := migrationAction(f.Group, f.Version, f.Kinds, nil)
		for i := 0; i < 3; i++ {
			if b := migrationAction(f.Group, f.Version, f.Kinds, nil); a != b {
				t.Fatalf("%s: %q != %q", f.Fact, a, b)
			}
		}
	}
}

// TestEveryHintFitsTheNextActionLimit: the text of every adapter fact is within
// the 256-byte limit with its table note, so no rule falls back to the generic
// text.
func TestEveryHintFitsTheNextActionLimit(t *testing.T) {
	for _, f := range adapterFacts {
		got := migrationAction(f.Group, f.Version, f.Kinds, nil)
		if len(got) > maxNextAction || strings.Contains(got, "Remove the named manifests or replace") || strings.Contains(got, "Migrate the named manifests") {
			t.Errorf("%s: %d bytes or generic: %s", f.Fact, len(got), got)
		}
		for _, k := range f.Kinds {
			// The long kind lists leave no room for a note.
			if n := hints[hintKey(f.Group, f.Version, k)].Note; n != "" && !strings.Contains(got, n) && !noNoteRoom[f.Fact] {
				t.Errorf("%s: note %q of %s dropped for space: %s", f.Fact, n, k, got)
			}
		}
	}
}

var noNoteRoom = map[string]bool{
	factPrefix + "admissionwebhook_v1beta1_removed_gvk_present":    true,
	factPrefix + "subjectaccessreview_v1beta1_removed_gvk_present": true,
	factPrefix + "flowcontrol_v1beta2_removed_gvk_present":         true,
}
