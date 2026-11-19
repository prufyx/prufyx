// SPDX-License-Identifier: AGPL-3.0-only

package constraintengine

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// fromToEqualityAllowlist pins every remaining direct ==/!= comparison of a
// from/to version outside the shared matcher (match.go), per file. None of
// them selects rules by transition:
//
//   - cncfprepare, projectprepare, and the communityapp native-route
//     dispatch: exact-pair preparers compare the caller's pair with their
//     own reviewed constants or reject from == to. They are not rule matching;
//     a preparer that becomes range-capable moves to the matcher.
//   - batchcheck: binds a batch item's declared pair to the input file's
//     declared versions (consistency of one declaration, not applicability).
//   - certmanagervalues: a separate, non-rule source contract.
//   - checkroutemetadata: descriptor construction and result ordering.
//   - supportinventory: release-transition bookkeeping for the inventory.
//   - rulecheck: the contribution validator's structural from != to check on
//     a candidate rule. Its closed rule schema has no range field, so a
//     contributed candidate can never carry a range.
//
// A new comparison anywhere fails this test. Route transition matching
// through RuleTransition instead of extending this list.
var fromToEqualityAllowlist = map[string]int{
	"internal/batchcheck/batchcheck.go":                        3,
	"internal/certmanagervalues/check.go":                      5,
	"internal/certmanagervalues/external.go":                   2,
	"internal/checkroutemetadata/catalog.go":                   4,
	"internal/cncfprepare/argocd.go":                           3,
	"internal/cncfprepare/argocd_latest.go":                    3,
	"internal/cncfprepare/argocd_resource_exclusions.go":       3,
	"internal/cncfprepare/buildpacks.go":                       1,
	"internal/cncfprepare/cilium.go":                           5,
	"internal/cncfprepare/cilium_cluster_name.go":              1,
	"internal/cncfprepare/cloudcustodian.go":                   6,
	"internal/cncfprepare/cnpg.go":                             1,
	"internal/cncfprepare/containerd.go":                       1,
	"internal/cncfprepare/coredns.go":                          4,
	"internal/cncfprepare/cortex.go":                           2,
	"internal/cncfprepare/crio.go":                             1,
	"internal/cncfprepare/crossplane.go":                       3,
	"internal/cncfprepare/cubefs.go":                           1,
	"internal/cncfprepare/emissary.go":                         3,
	"internal/cncfprepare/envoy.go":                            2,
	"internal/cncfprepare/etcd.go":                             9,
	"internal/cncfprepare/falco.go":                            4,
	"internal/cncfprepare/fluentd.go":                          4,
	"internal/cncfprepare/flux.go":                             2,
	"internal/cncfprepare/formats.go":                          2,
	"internal/cncfprepare/harbor.go":                           2,
	"internal/cncfprepare/intoto.go":                           1,
	"internal/cncfprepare/jaeger.go":                           1,
	"internal/cncfprepare/karmada.go":                          3,
	"internal/cncfprepare/keda.go":                             3,
	"internal/cncfprepare/knative.go":                          1,
	"internal/cncfprepare/kubeedge.go":                         3,
	"internal/cncfprepare/kubeflow.go":                         1,
	"internal/cncfprepare/kubernetes.go":                       1,
	"internal/cncfprepare/kubernetes_component_config.go":      1,
	"internal/cncfprepare/kubernetes_removed_apis.go":          1,
	"internal/cncfprepare/kubevirt.go":                         1,
	"internal/cncfprepare/kuma.go":                             3,
	"internal/cncfprepare/linkerd.go":                          3,
	"internal/cncfprepare/migrations.go":                       1,
	"internal/cncfprepare/nats.go":                             1,
	"internal/cncfprepare/opencost.go":                         2,
	"internal/cncfprepare/openfga.go":                          3,
	"internal/cncfprepare/opentelemetry.go":                    6,
	"internal/cncfprepare/prepare.go":                          4,
	"internal/cncfprepare/prometheus.go":                       4,
	"internal/cncfprepare/prometheus_alertmanager.go":          1,
	"internal/cncfprepare/prometheus_remote_write.go":          3,
	"internal/cncfprepare/spire.go":                            3,
	"internal/cncfprepare/strimzi.go":                          3,
	"internal/cncfprepare/tekton.go":                           3,
	"internal/cncfprepare/thanos.go":                           4,
	"internal/cncfprepare/tuf.go":                              1,
	"internal/cncfprepare/velero.go":                           4,
	"internal/communityapp/cncf_native_resource.go":            3,
	"internal/communityapp/project.go":                         2,
	"internal/maintainer/rulecheck/rulecheck.go":               1,
	"internal/maintainer/supportinventory/supportinventory.go": 1,
	"internal/projectprepare/fluent_bit.go":                    4,
	"internal/projectprepare/loki_structured_metadata.go":      4,
	"internal/projectprepare/mariadb.go":                       3,
	"internal/projectprepare/mariadb_operator.go":              2,
	"internal/projectprepare/osd_metadata.go":                  1,
	"internal/projectprepare/prepare.go":                       5,
	"internal/projectprepare/workload.go":                      5,
}

// TestNoDirectFromToEqualityOutsideMatcher scans every non-test Go file in the
// module (vendor excluded) for ==/!= where an operand is a from/to version: a
// selector named From/To/from/to, or an identifier named from/to/selectedFrom/
// selectedTo. Comparisons against the empty string are presence checks and
// are ignored. Only match.go may compare transitions directly.
func TestNoDirectFromToEqualityOutsideMatcher(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]int{}
	where := map[string][]string{}
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == "vendor" || entry.Name() == "testdata" || strings.HasPrefix(entry.Name(), ".") && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, _ := filepath.Rel(root, path)
		relative = filepath.ToSlash(relative)
		if relative == "internal/constraintengine/match.go" {
			return nil
		}
		fileSet := token.NewFileSet()
		file, err := parser.ParseFile(fileSet, path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(node ast.Node) bool {
			binary, ok := node.(*ast.BinaryExpr)
			if !ok || (binary.Op != token.EQL && binary.Op != token.NEQ) {
				return true
			}
			if emptyString(binary.X) || emptyString(binary.Y) {
				return true
			}
			if versionOperand(binary.X) || versionOperand(binary.Y) {
				found[relative]++
				where[relative] = append(where[relative], fileSet.Position(binary.Pos()).String())
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	files := make([]string, 0, len(found)+len(fromToEqualityAllowlist))
	seen := map[string]bool{}
	for name := range found {
		files, seen[name] = append(files, name), true
	}
	for name := range fromToEqualityAllowlist {
		if !seen[name] {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	for _, name := range files {
		if found[name] != fromToEqualityAllowlist[name] {
			t.Errorf("%s: %d direct from/to equality comparisons, allowlist pins %d; route transition matching through constraintengine.RuleTransition (%v)", name, found[name], fromToEqualityAllowlist[name], where[name])
		}
	}
}

func emptyString(expr ast.Expr) bool {
	literal, ok := ast.Unparen(expr).(*ast.BasicLit)
	return ok && literal.Kind == token.STRING && (literal.Value == `""` || literal.Value == "``")
}

func versionOperand(expr ast.Expr) bool {
	switch value := ast.Unparen(expr).(type) {
	case *ast.SelectorExpr:
		switch value.Sel.Name {
		case "From", "To", "from", "to":
			return true
		}
	case *ast.Ident:
		switch value.Name {
		case "from", "to", "selectedFrom", "selectedTo":
			return true
		}
	}
	return false
}
