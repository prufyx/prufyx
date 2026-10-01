// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"flag"
	"fmt"
	"io"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

type databaseCapabilitiesOutput struct {
	APIVersion              string `json:"apiVersion"`
	Profile                 string `json:"profile"`
	TargetPath              string `json:"targetPath"`
	Purpose                 string `json:"purpose"`
	ExternalBundleSchema    string `json:"externalBundleSchema"`
	PackSchema              string `json:"packSchema"`
	EngineCapabilityDigest  string `json:"engineCapabilityDigest"`
	PolicyID                string `json:"policyId"`
	PolicyDigest            string `json:"policyDigest"`
	RegistryDigest          string `json:"registryDigest"`
	LandscapeFileDigest     string `json:"landscapeFileDigest"`
	MaxBundleBytes          int    `json:"maxBundleBytes"`
	MaxEntries              int    `json:"maxEntries"`
	MaxFactsPerEntry        int    `json:"maxFactsPerEntry"`
	ExplicitSelectionOnly   bool   `json:"explicitSelectionOnly"`
	RequiresIndependentRoot bool   `json:"requiresIndependentRoot"`
	OfficialFeedConfigured  bool   `json:"officialFeedConfigured"`
	AutomaticRefreshEnabled bool   `json:"automaticRefreshEnabled"`
}

func (r runtime) databaseCapabilities(args []string) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, "Usage: prufyx db capabilities --profile cncf [--format human|json]\n\nReport the compiled public construction contract for an unsigned operator-provided CNCF target. This command reads no database and uses no network. It does not provide a signing key, trusted root, official feed, or automatic refresh.")
		return ExitOK
	}
	fs := flag.NewFlagSet("db capabilities", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	profile := fs.String("profile", "", "fixed profile: cncf")
	format := fs.String("format", "human", "human or json")
	if duplicateFlags(args) || fs.Parse(args) != nil || fs.NArg() != 0 || *profile != "cncf" || (*format != "human" && *format != "json") {
		return r.usage("invalid database capabilities arguments; use --help")
	}
	contract, err := cncfcheck.ExternalProfileContractForCNCF()
	if err != nil {
		return r.fail("CNCF capability contract integrity failure", ExitIntegrity)
	}
	output := databaseCapabilitiesOutput{
		APIVersion: "prufyx.io/knowledge-capabilities/v1", Profile: contract.Profile,
		TargetPath: contract.TargetPath, Purpose: contract.Purpose,
		ExternalBundleSchema: contract.Requirements.Schema, PackSchema: contract.Requirements.PackSchema,
		EngineCapabilityDigest: contract.Requirements.EngineCapabilityDigest,
		PolicyID:               contract.Requirements.PolicyID, PolicyDigest: contract.Requirements.PolicyDigest,
		RegistryDigest: contract.Requirements.RegistryDigest, LandscapeFileDigest: contract.Requirements.LandscapeFileDigest,
		MaxBundleBytes: contract.MaxBundleBytes, MaxEntries: contract.MaxEntries,
		MaxFactsPerEntry: contract.MaxFactsPerEntry, ExplicitSelectionOnly: contract.ExplicitSelectionOnly,
		RequiresIndependentRoot: contract.RequiresIndependentRoot,
	}
	if *format == "json" {
		return r.writeJSON(output, ExitOK)
	}
	_, writeErr := fmt.Fprintf(r.stdout, "knowledge capability profile: %s\ntarget path: %s\npurpose: %s\nexternal bundle schema: %s\npack schema: %s\nengine capability digest: %s\npolicy: %s (%s)\nregistry digest: %s\nlandscape digest: %s\nmax external target bytes: %d\nmax entries: %d\nmax facts per entry: %d\nexplicit selection only: %t\nindependent root required: %t\nofficial feed configured: false\nautomatic refresh enabled: false\nnetwork used: false\nstore used: false\nnext action: construct or verify an operator-provided unsigned target under this exact contract, then use independently managed signing and root distribution\n", output.Profile, output.TargetPath, output.Purpose, output.ExternalBundleSchema, output.PackSchema, output.EngineCapabilityDigest, output.PolicyID, output.PolicyDigest, output.RegistryDigest, output.LandscapeFileDigest, output.MaxBundleBytes, output.MaxEntries, output.MaxFactsPerEntry, output.ExplicitSelectionOnly, output.RequiresIndependentRoot)
	if writeErr != nil {
		return ExitIntegrity
	}
	return ExitOK
}
