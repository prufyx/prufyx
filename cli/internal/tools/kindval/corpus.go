// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/k8sremovals"
)

// corpusCase is one manifest of the behavioural corpus. Removal is the
// line the removal table says stops serving the API ("" for a control
// manifest that every line in the matrix serves).
type corpusCase struct {
	ID       string
	API      string
	Removal  string
	Manifest string
}

// specs are minimal bodies that make an object of the kind valid enough for
// a server dry run on a line that serves it. A kind without a body is still
// a complete probe for "no such API"; on a line that serves it the server
// answers "rejected" rather than "accepted".
var specs = map[string]string{
	"FlowSchema": `spec:
  priorityLevelConfiguration:
    name: exempt
  matchingPrecedence: 1000
  rules:
  - subjects:
    - kind: Group
      group:
        name: system:authenticated
    nonResourceRules:
    - verbs: ["get"]
      nonResourceURLs: ["/healthz"]
`,
	"PriorityLevelConfiguration": `spec:
  type: Limited
  limited:
    nominalConcurrencyShares: 5
    limitResponse:
      type: Reject
`,
	"ValidatingAdmissionPolicy": `spec:
  failurePolicy: Fail
  matchConstraints:
    resourceRules:
    - apiGroups: ["apps"]
      apiVersions: ["v1"]
      operations: ["CREATE"]
      resources: ["deployments"]
  validations:
  - expression: "object.spec.replicas <= 5"
`,
	"ValidatingAdmissionPolicyBinding": `spec:
  policyName: kindval-probe
  validationActions: ["Deny"]
`,
	"ServiceCIDR": `spec:
  cidrs: ["10.200.0.0/16"]
`,
	"IPAddress": `spec:
  parentRef:
    group: ""
    resource: services
    namespace: default
    name: kubernetes
`,
	"VolumeAttributesClass": `driverName: probe.example.invalid
parameters:
  tier: probe
`,
	"CronJob": `spec:
  schedule: "0 2 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: Never
          containers:
          - name: probe
            image: probe.example.invalid/probe:1
`,
	"PodDisruptionBudget": `spec:
  minAvailable: 1
  selector:
    matchLabels:
      app: probe
`,
	"HorizontalPodAutoscaler": `spec:
  maxReplicas: 2
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: probe
`,
	"Deployment": `spec:
  replicas: 1
  selector:
    matchLabels:
      app: probe
  template:
    metadata:
      labels:
        app: probe
    spec:
      containers:
      - name: probe
        image: probe.example.invalid/probe:1
`,
}

// namespaced kinds get a namespace; the rest are cluster scoped.
var namespaced = map[string]bool{"CronJob": true, "PodDisruptionBudget": true, "HorizontalPodAutoscaler": true, "Deployment": true}

// IPAddress objects are named by the address.
var fixedNames = map[string]string{"IPAddress": "10.96.0.250"}

func manifestFor(group, version, kind string) string {
	apiVersion := version
	if group != "" {
		apiVersion = group + "/" + version
	}
	name := "kindval-probe"
	if n, ok := fixedNames[kind]; ok {
		name = n
	}
	var b strings.Builder
	fmt.Fprintf(&b, "apiVersion: %s\nkind: %s\nmetadata:\n  name: %s\n", apiVersion, kind, name)
	if namespaced[kind] {
		b.WriteString("  namespace: default\n")
	}
	b.WriteString(specs[kind])
	return b.String()
}

// controls are APIs every line of the matrix serves: a scan must never block
// them, and every server accepts them.
var controls = []struct{ group, version, kind string }{
	{"apps", "v1", "Deployment"},
	{"flowcontrol.apiserver.k8s.io", "v1", "FlowSchema"},
	{"flowcontrol.apiserver.k8s.io", "v1", "PriorityLevelConfiguration"},
	{"admissionregistration.k8s.io", "v1", "ValidatingAdmissionPolicy"},
}

// corpus is every removal the table knows with a line at or above minLine
// (so the previous line is in the matrix too), the removals below it as
// "removed before the matrix" probes, and the controls.
func corpus(minLine string) []corpusCase {
	var out []corpusCase
	for _, rv := range k8sremovals.RemovedVersions() {
		for _, kind := range rv.Kinds {
			if _, known := specs[kind]; !known && lineLess(rv.Line, minLine) {
				continue // removed long before the matrix and no body: not informative
			}
			api := apiPair(rv.Group, rv.Version, kind)
			out = append(out, corpusCase{ID: caseID(api), API: api, Removal: rv.Line, Manifest: manifestFor(rv.Group, rv.Version, kind)})
		}
	}
	for _, c := range controls {
		api := apiPair(c.group, c.version, c.kind)
		out = append(out, corpusCase{ID: caseID(api), API: api, Manifest: manifestFor(c.group, c.version, c.kind)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func caseID(api string) string {
	return strings.NewReplacer("/", "_", " ", "_", ".", "-").Replace(api)
}

// runVerdicts applies every corpus case to the cluster with a server dry
// run and, when prufyx and the from version are given, scans each manifest
// for the hop fromVersion -> toVersion. Manifests are written under dir.
func runVerdicts(ctx context.Context, k kube, run runner, dir, line, prufyx, fromVersion, toVersion string, cases []corpusCase) (VerdictRun, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return VerdictRun{}, err
	}
	vr := VerdictRun{Schema: VerdictsSchema, Line: line, FromVersion: fromVersion, ToVersion: toVersion, Prufyx: prufyx}
	for _, c := range cases {
		path := filepath.Join(dir, c.ID+".yaml")
		if err := os.WriteFile(path, []byte(c.Manifest), 0o600); err != nil {
			return VerdictRun{}, err
		}
		vc := VerdictCase{ID: c.ID, API: c.API, Manifest: filepath.Base(path), Server: k.dryRunCreate(ctx, []byte(c.Manifest))}
		if prufyx != "" && fromVersion != "" {
			st := scan(ctx, run, prufyx, path, fromVersion, toVersion)
			vc.Scan = &st
		}
		vr.Cases = append(vr.Cases, vc)
	}
	return vr, nil
}

// scan runs `prufyx scan` for one manifest and one hop and reads the JSON
// report's verdict, gap reasons and matched rules.
func scan(ctx context.Context, run runner, prufyx, path, fromVersion, toVersion string) ScanTry {
	args := []string{"scan", path, "--from", "kubernetes=" + fromVersion, "--to", "kubernetes=" + toVersion,
		"--distribution", "official_upstream", "--resource-scope-complete", "--target-api-apply-required", "--format", "json"}
	out, errb, exit := run(ctx, prufyx, args, nil)
	st := ScanTry{From: fromVersion, To: toVersion, Exit: exit, Gaps: []string{}, Rules: []string{}}
	var report struct {
		Verdict string `json:"verdict"`
		Gaps    []struct {
			Reason string `json:"reason"`
		} `json:"gaps"`
		Findings []struct {
			RuleID string `json:"ruleId"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out, &report); err != nil {
		st.Error = fmt.Sprintf("no JSON report (exit %d): %s", exit, firstLine(strings.TrimSpace(string(errb))))
		return st
	}
	st.Verdict = report.Verdict
	for _, g := range report.Gaps {
		st.Gaps = append(st.Gaps, g.Reason)
	}
	for _, f := range report.Findings {
		st.Rules = append(st.Rules, f.RuleID)
	}
	sort.Strings(st.Gaps)
	sort.Strings(st.Rules)
	return st
}
