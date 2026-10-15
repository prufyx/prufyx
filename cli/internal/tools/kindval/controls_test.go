// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var fullCommit = regexp.MustCompile(`^[0-9a-f]{40}$`)

// The reviewed controls parse, have unique control.-prefixed ids, known
// kinds, at least two true and two false entries per kind, and every
// custom-resource release is pinned by a full commit.
func TestControlsFileIsWellFormed(t *testing.T) {
	entries, err := loadControls()
	if err != nil {
		t.Fatal(err)
	}
	count := map[string]map[string]int{}
	for _, e := range entries {
		if !strings.HasPrefix(e.ID, "control.") || !controlKinds[e.Kind] {
			t.Errorf("%s: id or kind %q", e.ID, e.Kind)
		}
		if count[e.Kind] == nil {
			count[e.Kind] = map[string]int{}
		}
		count[e.Kind][e.Control]++
		var releases []CRDRelease
		if e.Subject.Release != nil {
			releases = append(releases, *e.Subject.Release)
		}
		if e.Kind == KindCRDRemoval || e.Kind == KindCRDPair {
			for _, raw := range []json.RawMessage{e.Subject.From, e.Subject.To} {
				r, err := releaseSubject(raw)
				if err != nil {
					t.Errorf("%s: %v", e.ID, err)
				}
				releases = append(releases, r)
			}
		}
		for _, r := range releases {
			if !fullCommit.MatchString(r.Commit) || len(r.Files) == 0 {
				t.Errorf("%s: release %+v is not pinned by a 40-hex commit with files", e.ID, r)
			}
		}
		if strings.HasPrefix(e.Kind, "crd-") && !strings.HasPrefix(e.Subject.Project, "control.") {
			t.Errorf("%s: project %q does not start with control.", e.ID, e.Subject.Project)
		}
		if len(e.Evidence) == 0 || !strings.Contains(string(e.Evidence), "https://github.com/") {
			t.Errorf("%s: no upstream citation in evidence", e.ID)
		}
	}
	for kind := range controlKinds {
		if count[kind][ControlTrue] < 2 || count[kind][ControlFalse] < 2 {
			t.Errorf("kind %s: %d true and %d false controls, want at least 2 of each", kind, count[kind][ControlTrue], count[kind][ControlFalse])
		}
	}
}

// Every expansion of the controls is a valid v2 claims file, for any
// matrix, and has unique ids.
func TestControlsExpandToValidClaims(t *testing.T) {
	all := map[string]bool{}
	for kind := range controlKinds {
		all[kind] = true
	}
	for _, matrix := range [][]string{
		{"1.24", "1.25", "1.26", "1.27", "1.28", "1.29", "1.30", "1.31", "1.32", "1.33", "1.34", "1.35", "1.36", "1.37"},
		{"1.31", "1.32"},
		{"1.36", "1.37"},
		{"1.30", "1.32"},
	} {
		claims := reviewedV2Claims(KubernetesClaims(matrix), matrix)
		if err := claims.Validate(); err != nil {
			t.Fatalf("%v: %v", matrix, err)
		}
		controls := ExpandControls(mustControls(), matrix, all)
		ids := map[string]bool{}
		for _, c := range controls {
			if ids[c.ID] {
				t.Fatalf("%v: duplicate control %s", matrix, c.ID)
			}
			ids[c.ID] = true
		}
	}
	// Hops are between lines one minor apart only: a sparse matrix has no
	// removal control for 1.30 -> 1.32.
	for _, c := range ExpandControls(mustControls(), []string{"1.30", "1.32"}, map[string]bool{KindK8sRemoval: true}) {
		t.Errorf("sparse matrix got removal control %s", c.ID)
	}
	got := map[string]bool{}
	for _, c := range ExpandControls(mustControls(), []string{"1.31", "1.32"}, all) {
		got[c.ID] = true
	}
	for _, id := range []string{
		"control.served.apps_v1_Deployment.served.1.31",
		"control.served.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.not_served.1.32",
		"control.removal.apps_v1_Deployment.1.31-to-1.32",
		"control.removal.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.1.31-to-1.32",
		"control.crd-pair.external-snapshotter.v5.0.1-to-v6.0.0",
	} {
		if !got[id] {
			t.Errorf("missing control %s", id)
		}
	}
	if got["control.served.flowcontrol.apiserver.k8s.io_v1beta3_FlowSchema.not_served.1.31"] || got["control.removal.batch_v1beta1_CronJob.1.24-to-1.25"] {
		t.Error("a control was expanded outside its lines")
	}
}

// v2Claims makes a v2 claims file of the claims and the reviewed controls
// of their kinds for the matrix.
func reviewedV2Claims(claims []Claim, lines []string) Claims {
	out := Claims{Schema: ClaimsSchemaV2, Lines: lines, Claims: append([]Claim(nil), claims...)}
	out.Claims = append(out.Claims, ExpandControls(mustControls(), lines, claimKinds(claims))...)
	return out
}

// A v2 claims file must carry exactly the reviewed controls: none missing,
// none added, none changed, and no control member in a v1 file.
func TestValidateKeepsControlsReviewed(t *testing.T) {
	lines := []string{"1.31", "1.32"}
	good := reviewedV2Claims(KubernetesClaims(lines), lines)
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	mutate := func(f func(c *Claims)) Claims {
		data, _ := json.Marshal(good)
		var c Claims
		if err := json.Unmarshal(data, &c); err != nil {
			t.Fatal(err)
		}
		f(&c)
		return c
	}
	cases := map[string]Claims{
		"dropped": mutate(func(c *Claims) { c.Claims = c.Claims[:len(c.Claims)-1] }),
		"flipped": mutate(func(c *Claims) {
			last := &c.Claims[len(c.Claims)-1]
			if last.Control == ControlTrue {
				last.Control = ControlFalse
			} else {
				last.Control = ControlTrue
			}
		}),
		"edited": mutate(func(c *Claims) { c.Claims[len(c.Claims)-1].Subject.Version = "v9" }),
		"invented": mutate(func(c *Claims) {
			c.Claims = append(c.Claims, Claim{ID: "control.mine", Kind: KindServedAPI, Subject: Subject{Line: "1.32", Version: "v1", Kind: "Pod"}, Expect: ExpectServed, Control: ControlTrue})
		}),
		"no lines": mutate(func(c *Claims) { c.Lines = nil }),
		"other lines": mutate(func(c *Claims) {
			c.Lines = []string{"1.32"}
		}),
		"control id without control": mutate(func(c *Claims) {
			c.Claims = append(c.Claims, servedAPIClaim("1.32", "apps", "v1", "Deployment", ExpectServed, "t"))
			c.Claims[len(c.Claims)-1].ID = "control.plain"
		}),
		"control in v1": {Schema: ClaimsSchema, Claims: []Claim{{ID: "control.x", Kind: KindServedAPI, Subject: Subject{Line: "1.32", Version: "v1", Kind: "Pod"}, Expect: ExpectServed, Control: ControlTrue}}},
		"lines in v1":   {Schema: ClaimsSchema, Lines: lines, Claims: []Claim{}},
	}
	for name, c := range cases {
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A v1 file keeps working as before, even with an id that starts with
	// control.
	v1 := Claims{Schema: ClaimsSchema, Claims: []Claim{servedAPIClaim("1.32", "apps", "v1", "Deployment", ExpectServed, "t")}}
	v1.Claims[0].ID = "control.legacy"
	if err := v1.Validate(); err != nil {
		t.Fatal(err)
	}
}

// `kindval claims --schema v2` adds the controls of the kinds present; v1
// stays as it was; a merged file may not carry controls.
func TestClaimsCommandWritesControls(t *testing.T) {
	dir := t.TempDir()
	crd := filepath.Join(dir, "crd.json")
	data, _ := json.Marshal(gadgetClaims(true))
	if err := os.WriteFile(crd, data, 0o600); err != nil {
		t.Fatal(err)
	}
	v1 := filepath.Join(dir, "v1.json")
	if code := run([]string{"claims", "--lines", "1.31,1.32", "--crd", crd, "--out", v1}, os.Stdout, os.Stderr); code != 0 {
		t.Fatalf("v1 exit %d", code)
	}
	raw, _ := os.ReadFile(v1)
	if strings.Contains(string(raw), `"control"`) || strings.Contains(string(raw), `"lines"`) || !strings.Contains(string(raw), ClaimsSchema) {
		t.Fatalf("v1 claims carry v2 members:\n%s", raw)
	}
	v2 := filepath.Join(dir, "v2.json")
	if code := run([]string{"claims", "--lines", "1.31,1.32", "--crd", crd, "--schema", "v2", "--out", v2}, os.Stdout, os.Stderr); code != 0 {
		t.Fatalf("v2 exit %d", code)
	}
	c, err := loadClaims(v2)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, cl := range c.Claims {
		if cl.Control != "" {
			kinds[cl.Kind]++
		}
	}
	for _, kind := range []string{KindServedAPI, KindK8sRemoval, KindCRDVersion, KindCRDRemoval} {
		if kinds[kind] == 0 {
			t.Errorf("no %s control in %v", kind, kinds)
		}
	}
	if kinds[KindCRDPair] != 0 {
		t.Errorf("crd-pair controls added without a crd-pair claim: %v", kinds)
	}
	// The control pairs join the pairs the crd run installs.
	found := false
	for _, p := range c.Pairs() {
		found = found || p.Project == "control.external-snapshotter"
	}
	if !found {
		t.Fatalf("pairs %+v", c.Pairs())
	}
	// Feeding a v2 claims file back as --crd is refused.
	if code := run([]string{"claims", "--lines", "1.31,1.32", "--crd", v2, "--schema", "v2", "--out", filepath.Join(dir, "again.json")}, os.Stdout, os.Stderr); code != 1 {
		t.Fatalf("re-fed v2 claims: exit %d", code)
	}
	if code := run([]string{"claims", "--lines", "1.31", "--schema", "v3", "--out", filepath.Join(dir, "x.json")}, os.Stdout, os.Stderr); code != 1 {
		t.Fatalf("--schema v3: exit %d", code)
	}
}

// A merged claims file may not use the control member or a control. id,
// whatever its schema: the error names the file.
func TestMergedFileWithControlIDIsRefused(t *testing.T) {
	dir := t.TempDir()
	extra := filepath.Join(dir, "extra.json")
	legacy := Claims{Schema: ClaimsSchema, Claims: []Claim{servedAPIClaim("1.32", "apps", "v1", "Deployment", ExpectServed, "t")}}
	legacy.Claims[0].ID = "control.legacy"
	data, _ := json.Marshal(legacy)
	if err := os.WriteFile(extra, data, 0o600); err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	if code := run([]string{"claims", "--lines", "1.31,1.32", "--crd", extra, "--out", filepath.Join(dir, "out.json")}, os.Stdout, &stderr); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stderr.String(), extra) || !strings.Contains(stderr.String(), "control.legacy") {
		t.Fatalf("error does not name the file and claim: %s", stderr.String())
	}
}

// A line named twice gives each control once; a v2 file that names a line
// twice is refused.
func TestDuplicateLinesAreDeduplicated(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "claims.json")
	if code := run([]string{"claims", "--lines", "1.31,1.32,1.32,1.31", "--schema", "v2", "--out", out}, os.Stdout, os.Stderr); code != 0 {
		t.Fatalf("exit %d", code)
	}
	c, err := loadClaims(out)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.Lines, ",") != "1.31,1.32" {
		t.Fatalf("lines %v", c.Lines)
	}
	twice := c
	twice.Lines = []string{"1.31", "1.32", "1.32"}
	if err := twice.Validate(); err == nil {
		t.Fatal("a line named twice is accepted")
	}
	ids := map[string]bool{}
	for _, ctl := range ExpandControls(mustControls(), []string{"1.32", "1.31", "1.32"}, map[string]bool{KindServedAPI: true, KindK8sRemoval: true}) {
		if ids[ctl.ID] {
			t.Fatalf("duplicate control %s", ctl.ID)
		}
		ids[ctl.ID] = true
	}
}

// Removal claims alone bring the served-API controls of their lines too: a
// removal is decided on the served APIs of both lines.
func TestRemovalClaimsBringServedAPIControls(t *testing.T) {
	kinds := claimKinds([]Claim{removalClaim("r", "flowcontrol.apiserver.k8s.io", "v1beta3", "FlowSchema", "")})
	if !kinds[KindServedAPI] || !kinds[KindK8sRemoval] {
		t.Fatalf("kinds %v", kinds)
	}
	if kinds := claimKinds([]Claim{servedAPIClaim("1.32", "apps", "v1", "Deployment", ExpectServed, "t")}); kinds[KindK8sRemoval] {
		t.Fatalf("served-API claims alone bring removal controls: %v", kinds)
	}
}
