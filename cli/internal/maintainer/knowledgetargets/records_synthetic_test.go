// SPDX-License-Identifier: AGPL-3.0-only

//go:build prufyx_synthetic_knowledge

package knowledgetargets

// Run with: go test -tags prufyx_synthetic_knowledge ./internal/maintainer/knowledgetargets/

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

const recordEvidence = `{"basis":"reviewed","reviewedAt":"2026-09-23T00:00:00Z","validUntil":"2026-12-20T00:00:00Z","sources":[{"id":"s","url":"https://github.com/kubernetes/website/blob/9f1af2971c32124bff0a1f42255ba5a2f3c8a16f/content/en/docs/reference/using-api/deprecation-guide.md","revision":"9f1af2971c32124bff0a1f42255ba5a2f3c8a16f","contentDigest":"sha256:96f34a49cbdd7bd53008cc7b7cc8aff58c373ad323e64eef0155cbbc44494f61","startLine":40,"endLine":49}]}`

// servedLists is a served-list section for kubernetes lines 1.<first> to
// 1.<last>, each naming apis synthetic "v1 K<n>" pairs.
func servedLists(first, last, apis int) json.RawMessage {
	var pairs []string
	for i := 0; i < apis; i++ {
		pairs = append(pairs, fmt.Sprintf("v1 K%05d", i))
	}
	encoded, _ := json.Marshal(pairs)
	var records []string
	for minor := first; minor <= last; minor++ {
		records = append(records, fmt.Sprintf(`{"component":"pkg:github/kubernetes/kubernetes","line":"1.%d","completeness":"COMPLETE_SERVED_API_LIST_FOR_LINE","apis":%s,"evidence":%s}`, minor, encoded, recordEvidence))
	}
	return json.RawMessage("[" + strings.Join(records, ",") + "]")
}

func install(t *testing.T, records cncfcheck.SyntheticRecords) {
	t.Helper()
	restore, err := cncfcheck.UseSyntheticRecords(nil, nil, records)
	if err != nil {
		t.Fatalf("synthetic records refused: %v", err)
	}
	t.Cleanup(restore)
}

// TestBuildCarriesRecordsAndCheckSizeMeasuresThem: the published per-project
// layout built from a pack with served lists puts them in the kubernetes
// target only, check-size measures that target with its records, and the
// single-target layout carries them as well.
func TestBuildCarriesRecordsAndCheckSizeMeasuresThem(t *testing.T) {
	var plain int64
	{
		_, projects, err := Build("7", nil)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range projects {
			if p.Path == cncfcheck.ProjectTargetPath("kubernetes") {
				plain = int64(len(p.Bytes))
			}
		}
	}
	install(t, cncfcheck.SyntheticRecords{ServedAPIs: servedLists(32, 37, 600)})
	out := filepath.Join(t.TempDir(), "targets")
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"build", "--revision", "7", "--output-dir", out}, &stdout, &stderr); code != 0 {
		t.Fatalf("build code=%d stderr=%s", code, stderr.String())
	}
	index, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(cncfcheck.ExternalIndexTargetPath)))
	if err != nil || !bytes.Contains(index, []byte(cncfcheck.ExternalIndexSchemaRecords)) {
		t.Fatalf("index %s: %v", index, err)
	}
	found, err := targetsInDir(out)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range found {
		raw, _ := os.ReadFile(filepath.Join(out, filepath.FromSlash(target.Path)))
		carries := bytes.Contains(raw, []byte(`"servedAPIs"`))
		if carries != (target.Path == cncfcheck.ProjectTargetPath("kubernetes")) {
			t.Fatalf("%s carries served lists: %v", target.Path, carries)
		}
		if carries && target.Bytes <= plain {
			t.Fatalf("kubernetes target %d bytes, without records %d", target.Bytes, plain)
		}
	}
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"check-size"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "single-target layout") {
		t.Fatalf("check-size code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
}

// TestCheckSizeAlarmsOnRecords: records that push the kubernetes target to
// the alarm size fail check-size, and records past the per-target cap make
// the layout unbuildable (the target parser refuses it) rather than
// publishable.
func TestCheckSizeAlarmsOnRecords(t *testing.T) {
	// About 52 KB per list: 17 lists put the target in the alarm band.
	install(t, cncfcheck.SyntheticRecords{ServedAPIs: servedLists(10, 26, 4096)})
	var stdout, stderr bytes.Buffer
	code := Run([]string{"check-size"}, &stdout, &stderr)
	if code != 1 || !strings.Contains(stderr.String(), "size alarm: target "+cncfcheck.ProjectTargetPath("kubernetes")) {
		t.Fatalf("check-size code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	install(t, cncfcheck.SyntheticRecords{ServedAPIs: servedLists(10, 40, 4096)})
	stdout.Reset()
	stderr.Reset()
	if code := Run([]string{"check-size"}, &stdout, &stderr); code != 2 || !strings.Contains(stderr.String(), "cannot be split") {
		t.Fatalf("over the cap: code=%d stderr=%s", code, stderr.String())
	}
}
