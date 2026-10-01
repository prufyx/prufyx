// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func TestDatabaseCapabilitiesReportsExactCNCFContract(t *testing.T) {
	contract, err := cncfcheck.ExternalProfileContractForCNCF()
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	r := runtime{stdout: &stdout, stderr: &stderr}
	if code := r.databaseCapabilities([]string{"--profile", "cncf", "--format", "json"}); code != ExitOK || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	var got databaseCapabilitiesOutput
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.APIVersion != "prufyx.io/knowledge-capabilities/v1" || got.Profile != contract.Profile || got.TargetPath != contract.TargetPath || got.Purpose != contract.Purpose || got.ExternalBundleSchema != contract.Requirements.Schema || got.EngineCapabilityDigest != contract.Requirements.EngineCapabilityDigest || got.MaxBundleBytes != contract.MaxBundleBytes || got.MaxEntries != contract.MaxEntries || got.MaxFactsPerEntry != contract.MaxFactsPerEntry || !got.ExplicitSelectionOnly || !got.RequiresIndependentRoot || got.OfficialFeedConfigured || got.AutomaticRefreshEnabled {
		t.Fatalf("capabilities=%+v contract=%+v", got, contract)
	}
}

func TestDatabaseCapabilitiesRejectsMalformedArgumentsWithoutEchoingThem(t *testing.T) {
	canary := "PRIVATE_ARGUMENT_CANARY"
	for _, args := range [][]string{
		{"--profile", "cncf", "--profile", "cncf"},
		{"--profile", "cncf", "--format", "xml"},
		{"--profile", canary},
		{"--profile", "cncf", canary},
	} {
		var stdout, stderr bytes.Buffer
		r := runtime{stdout: &stdout, stderr: &stderr}
		if code := r.databaseCapabilities(args); code != ExitUsage {
			t.Fatalf("args=%q code=%d stdout=%s stderr=%s", args, code, stdout.String(), stderr.String())
		}
		if strings.Contains(stdout.String()+stderr.String(), canary) {
			t.Fatalf("canary leaked for args=%q", args)
		}
	}
}
