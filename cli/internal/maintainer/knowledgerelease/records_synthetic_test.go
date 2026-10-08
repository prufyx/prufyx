// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package knowledgerelease

// Run with: go test -tags prufyx_synthetic_knowledge ./internal/maintainer/knowledgerelease/

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
)

const servedSection = `[{"component":"pkg:github/kubernetes/kubernetes","line":"1.29","completeness":"COMPLETE_SERVED_API_LIST_FOR_LINE","apis":["apps/v1 Deployment","v1 ConfigMap"],"evidence":{"basis":"reviewed","reviewedAt":"2026-09-23T00:00:00Z","validUntil":"2026-11-30T00:00:00Z","sources":[{"id":"s","url":"https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/docs/reference/using-api/deprecation-guide.md","revision":"9f1af2971c32124bff0a1f42255ba5a2f3c8a16f","contentDigest":"sha256:96f34a49cbdd7bd53008cc7b7cc8aff58c373ad323e64eef0155cbbc44494f61","startLine":40,"endLine":49}]}}]`

// TestReleaseCarriesRecords (EXTPACK, FEED-1): the one-command release of a
// pack with a served-API list signs a records envelope that carries it, the
// release expires no later than the record, and the signed package verifies
// as a knowledge database package.
func TestReleaseCarriesRecords(t *testing.T) {
	restore, err := cncfcheck.UseSyntheticRecords(nil, nil, cncfcheck.SyntheticRecords{ServedAPIs: json.RawMessage(servedSection)})
	if err != nil {
		t.Fatal(err)
	}
	defer restore()
	o := fixture(t)
	result, err := Run(o)
	if err != nil {
		t.Fatalf("release of a pack with records: %v", err)
	}
	target, err := os.ReadFile(filepath.Join(o.OutputDir, "constraints.v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(target, []byte(`{"schema":"prufyx.io/operator-cncf-knowledge/v1alpha2"`)) || !bytes.Contains(target, []byte(`"servedAPIs":[{"component":"pkg:github/kubernetes/kubernetes"`)) {
		t.Fatalf("target does not carry the served list: %.200s", target)
	}
	if result.Expires > "2026-11-30T00:00:00Z" {
		t.Fatalf("release expires %s, after the record", result.Expires)
	}
	if _, err := knowledge.VerifyConstraints(knowledge.VerifyRequest{
		PackagePath: filepath.Join(o.OutputDir, "cncf-"+o.Revision+".tar"), BootstrapRootPath: o.Root, BootstrapRootDigest: o.RootDigest,
	}); err != nil {
		t.Fatalf("the signed package does not verify: %v", err)
	}
}
