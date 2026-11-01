// SPDX-License-Identifier: AGPL-3.0-only

package cliflags

import (
	"fmt"
	"testing"
)

// Each guard of the scanner has a scenario: fixtures that pass with the guard
// on and must fail with it off. TestGuardsAreLoadBearing is the mutation
// check: it switches every guard off in turn through the seam (scan takes the
// guards as a parameter; Scan, the only exported entry, passes the defaults,
// so no production path can reach a switched-off guard) and requires the
// named test to fail.

func fixturesScenario(names ...string) func(guards) error {
	return func(g guards) error { return runFixtures(g, names...) }
}

// scenarioLimits needs no fixture: a tree above the limits must be withheld.
func scenarioLimits(g guards) error {
	g.lim = limits{dirs: 3, filesPerDir: 2048, depth: 16, fileBytes: 2 << 20, files: 60000, totalBytes: 256 << 20, packages: 4096, follows: 20000}
	files := map[string]string{
		"go.mod":          goMod,
		"cmd/t/main.go":   "package main\n\nfunc main() {}\n",
		"internal/a/a.go": "package a\n",
		"internal/b/b.go": "package b\n",
		"internal/c/c.go": "package c\n",
	}
	res, err := scan(nilCtx(), newMem(files), Target{Repo: repo}, commitA, g)
	if err != nil {
		return err
	}
	if len(res.Ledger) != 1 || res.Ledger[0].Code != ReasonTooLarge || res.Attestable() {
		return fmt.Errorf("a tree above the directory limit is not withheld: %v", ledgerStrings(res.Ledger))
	}
	return nil
}

type guardScenario struct {
	run func(guards) error
	off func(*guards)
}

var guardScenarios = map[string]guardScenario{
	"TestGuardImportAllowlist":   {fixturesScenario("idiom_klog", "binaries_auto"), func(g *guards) { g.imports = false }},
	"TestGuardDynamicNames":      {fixturesScenario("dynamic_const", "dynamic_concat", "dynamic_sprintf", "dynamic_urfave"), func(g *guards) { g.dynamic = false }},
	"TestGuardLoop":              {fixturesScenario("loop"), func(g *guards) { g.loop = false }},
	"TestGuardBuildConstraints":  {fixturesScenario("build_tag_line", "build_tag_plus", "build_tag_suffix", "build_ignore"), func(g *guards) { g.buildTag = false }},
	"TestGuardGOOSBranch":        {fixturesScenario("build_goos_if", "build_goos_switch"), func(g *guards) { g.goos = false }},
	"TestGuardInitRegistration":  {fixturesScenario("init_registration", "init_callback", "init_cobra", "init_library"), func(g *guards) { g.initReg = false }},
	"TestGuardUnprovableReceive": {fixturesScenario("delegated_receiver", "delegated_orphan_param", "kingpin_thanos"), func(g *guards) { g.tripwire = false }},
	"TestGuardEscapingFlagSet":   {fixturesScenario("delegated_escape", "delegated_methodvalue"), func(g *guards) { g.escape = false }},
	"TestGuardUnresolvedCallee":  {fixturesScenario("delegated_callee"), func(g *guards) { g.delegated = false }},
	"TestGuardDelegationDepth":   {fixturesScenario("delegation_depth3", "delegation_depth4"), func(g *guards) { g.depthLimit = false }},
	"TestGuardNormalizeFunc":     {fixturesScenario("normalize_func"), func(g *guards) { g.normalize = false }},
	"TestGuardGlobalFlagset":     {fixturesScenario("global_flagset", "idiom_klog"), func(g *guards) { g.global = false }},
	"TestGuardDuplicate":         {fixturesScenario("duplicate", "cobra_tree"), func(g *guards) { g.duplicate = false }},
	"TestGuardArgsRewritten":     {fixturesScenario("args_assign", "args_setargs", "args_len", "cobra_tree", "kingpin_prometheus"), func(g *guards) { g.argsRewrite = false }},
	"TestGuardShorthand":         {fixturesScenario("shorthand_pflag", "shorthand_kingpin", "urfave_v1"), func(g *guards) { g.shorthand = false }},
	"TestGuardUrfaveAliases":     {fixturesScenario("urfave_v2"), func(g *guards) { g.aliases = false }},
	"TestGuardMemberContract":    {fixturesScenario("names", "urfave_v1"), func(g *guards) { g.nameClass = false }},
	"TestGuardBuiltinNames":      {fixturesScenario("builtin_names"), func(g *guards) { g.builtin = false }},
	"TestGuardUnlistedMethods":   {fixturesScenario("pflag_unlisted_method", "pflag_pkg_addflag", "pflag_pkg_addflagset", "delegated_addflagset", "delegated_addgoflag"), func(g *guards) { g.unlisted = false }},
	"TestGuardRegistrationTable": {fixturesScenario("pflag_varpf_method"), func(g *guards) {
		g.verbs = map[string]verbInfo{}
		for k, v := range regVerbs {
			if k != "VarPF" {
				g.verbs[k] = v
			}
		}
	}},
	"TestGuardArgsParser":       {fixturesScenario("args_handwritten_parser", "args_interface_parser", "cobra_tree", "urfave_v2"), func(g *guards) { g.argsParser = false }},
	"TestGuardReachability":     {fixturesScenario("unreachable_function", "reachable_by_reference", "cobra_tree"), func(g *guards) { g.reach = false }},
	"TestGuardStdlibDenylist":   {fixturesScenario("import_cgo", "import_httptest"), func(g *guards) { g.stdDeny = false }},
	"TestGuardReplacedModules":  {fixturesScenario("replace_allowlisted", "replace_block_allowlisted", "replace_unrelated", "vendor_replace", "vendor_plain"), func(g *guards) { g.vendorMod = false }},
	"TestGuardUrfaveElements":   {fixturesScenario("urfave_custom_flag", "urfave_var_list"), func(g *guards) { g.urfaveElems = false }},
	"TestGuardUrfaveGeneric":    {fixturesScenario("urfave_v3_flagbase"), func(g *guards) { g.urfaveGen = false }},
	"TestGuardIgnoredFileNames": {fixturesScenario("go_tool_ignored_names"), func(g *guards) { g.fileNames = false }},
	"TestGuardKingpinNegation":  {fixturesScenario("kingpin_negation"), func(g *guards) { g.negation = false }},
	"TestGuardStaleExclusion":   {fixturesScenario("exclusion_stale"), func(g *guards) { g.excludeOnly = false }},
	"TestGuardLimits":           {scenarioLimits, func(g *guards) { g.limits = false }},
	"TestGuardParseErrors":      {fixturesScenario("parse_error"), func(g *guards) { g.parse = false }},
}

func TestGuardImportAllowlist(t *testing.T)   { mustGuard(t, "TestGuardImportAllowlist") }
func TestGuardDynamicNames(t *testing.T)      { mustGuard(t, "TestGuardDynamicNames") }
func TestGuardLoop(t *testing.T)              { mustGuard(t, "TestGuardLoop") }
func TestGuardBuildConstraints(t *testing.T)  { mustGuard(t, "TestGuardBuildConstraints") }
func TestGuardGOOSBranch(t *testing.T)        { mustGuard(t, "TestGuardGOOSBranch") }
func TestGuardInitRegistration(t *testing.T)  { mustGuard(t, "TestGuardInitRegistration") }
func TestGuardUnprovableReceive(t *testing.T) { mustGuard(t, "TestGuardUnprovableReceive") }
func TestGuardEscapingFlagSet(t *testing.T)   { mustGuard(t, "TestGuardEscapingFlagSet") }
func TestGuardUnresolvedCallee(t *testing.T)  { mustGuard(t, "TestGuardUnresolvedCallee") }
func TestGuardDelegationDepth(t *testing.T)   { mustGuard(t, "TestGuardDelegationDepth") }
func TestGuardNormalizeFunc(t *testing.T)     { mustGuard(t, "TestGuardNormalizeFunc") }
func TestGuardGlobalFlagset(t *testing.T)     { mustGuard(t, "TestGuardGlobalFlagset") }
func TestGuardDuplicate(t *testing.T)         { mustGuard(t, "TestGuardDuplicate") }
func TestGuardArgsRewritten(t *testing.T)     { mustGuard(t, "TestGuardArgsRewritten") }
func TestGuardShorthand(t *testing.T)         { mustGuard(t, "TestGuardShorthand") }
func TestGuardUrfaveAliases(t *testing.T)     { mustGuard(t, "TestGuardUrfaveAliases") }
func TestGuardMemberContract(t *testing.T)    { mustGuard(t, "TestGuardMemberContract") }
func TestGuardBuiltinNames(t *testing.T)      { mustGuard(t, "TestGuardBuiltinNames") }
func TestGuardKingpinNegation(t *testing.T)   { mustGuard(t, "TestGuardKingpinNegation") }
func TestGuardStaleExclusion(t *testing.T)    { mustGuard(t, "TestGuardStaleExclusion") }
func TestGuardLimits(t *testing.T)            { mustGuard(t, "TestGuardLimits") }
func TestGuardParseErrors(t *testing.T)       { mustGuard(t, "TestGuardParseErrors") }

func TestGuardUnlistedMethods(t *testing.T)   { mustGuard(t, "TestGuardUnlistedMethods") }
func TestGuardRegistrationTable(t *testing.T) { mustGuard(t, "TestGuardRegistrationTable") }
func TestGuardArgsParser(t *testing.T)        { mustGuard(t, "TestGuardArgsParser") }
func TestGuardReachability(t *testing.T)      { mustGuard(t, "TestGuardReachability") }
func TestGuardStdlibDenylist(t *testing.T)    { mustGuard(t, "TestGuardStdlibDenylist") }
func TestGuardReplacedModules(t *testing.T)   { mustGuard(t, "TestGuardReplacedModules") }
func TestGuardUrfaveElements(t *testing.T)    { mustGuard(t, "TestGuardUrfaveElements") }
func TestGuardUrfaveGeneric(t *testing.T)     { mustGuard(t, "TestGuardUrfaveGeneric") }
func TestGuardIgnoredFileNames(t *testing.T)  { mustGuard(t, "TestGuardIgnoredFileNames") }

func mustGuard(t *testing.T, name string) {
	t.Helper()
	if err := guardScenarios[name].run(defaultGuards()); err != nil {
		t.Fatal(err)
	}
}

// TestGuardsAreLoadBearing: with any one guard off, its named test must fail.
func TestGuardsAreLoadBearing(t *testing.T) {
	for name, sc := range guardScenarios {
		g := defaultGuards()
		sc.off(&g)
		if err := sc.run(g); err == nil {
			t.Errorf("%s: switching its guard off changes nothing", name)
		}
	}
	for name, sc := range ledgerScenarios {
		g := defaultLedgerGuards()
		sc.off(&g)
		if err := sc.run(g); err == nil {
			t.Errorf("%s: switching its guard off changes nothing", name)
		}
	}
	// Every scenario is also wired to a test of the same name.
	if len(guardScenarios) != 31 || len(ledgerScenarios) != 8 {
		t.Errorf("scenario count changed: %d guards, %d ledger", len(guardScenarios), len(ledgerScenarios))
	}
}
