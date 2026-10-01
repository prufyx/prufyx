// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"path/filepath"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/maintainer/knowledgepublish"
)

func runKnowledgePublish(args []string, stdout io.Writer) error {
	if len(args) == 0 {
		return knowledgePublishError()
	}
	switch args[0] {
	case "prepare-targets":
		return runPrepareTargets(args[1:])
	case "prepare-snapshot":
		return runPrepareSnapshot(args[1:])
	case "prepare-timestamp":
		return runPrepareTimestamp(args[1:])
	case "prepare-root-transition":
		return runPrepareRootTransition(args[1:], stdout)
	case "finalize-role":
		return runFinalizeRole(args[1:])
	case "finalize-root-transition":
		return runFinalizeRootTransition(args[1:], stdout)
	case "finalize-rotated-package":
		return runFinalizeRotatedPackage(args[1:], stdout)
	case "finalize-package":
		return runFinalizeKnowledgePackage(args[1:], stdout)
	default:
		return knowledgePublishError()
	}
}

func runFinalizeRotatedPackage(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("knowledge-publish finalize-rotated-package", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var initialRoot, initialDigest, target, targets, snapshot, timestamp, output string
	var successors []string
	flags.StringVar(&initialRoot, "initial-root", "", "independently pinned initial root")
	flags.StringVar(&initialDigest, "initial-root-digest", "", "exact initial root SHA-256")
	flags.Func("successor-root", "finalized successor root; repeat in N+1 order", func(v string) error { successors = append(successors, v); return nil })
	flags.StringVar(&target, "target", "", "complete CNCF external target")
	flags.StringVar(&targets, "targets", "", "finalized targets metadata")
	flags.StringVar(&snapshot, "snapshot", "", "finalized snapshot metadata")
	flags.StringVar(&timestamp, "timestamp", "", "finalized timestamp metadata")
	flags.StringVar(&output, "output", "", "new anchored rotated package")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			if _, e := fmt.Fprintln(stdout, "usage: prufyx-maintainer knowledge-publish finalize-rotated-package --initial-root ABS --initial-root-digest sha256:... --successor-root ABS [--successor-root ABS ...] --target ABS --targets ABS --snapshot ABS --timestamp ABS --output ABS"); e != nil {
				return e
			}
			_, e := fmt.Fprintln(stdout, "supply 1-8 finalized successors in N+1..K order; the package is for a client currently trusting N. The receipt is stateless verification, not store eligibility.")
			return e
		}
		return knowledgePublishError()
	}
	if flags.NArg() != 0 || initialRoot == "" || initialDigest == "" || target == "" || targets == "" || snapshot == "" || timestamp == "" || output == "" || !filepath.IsAbs(output) || len(successors) == 0 || len(successors) > 8 {
		return knowledgePublishError()
	}
	initialRaw, e1 := readPublishInput(initialRoot, knowledgepublish.MaxRootBytes)
	targetRaw, e2 := readPublishInput(target, knowledgepublish.MaxTargetBytes)
	targetsRaw, e3 := readPublishInput(targets, knowledgepublish.MaxRoleBytes)
	snapshotRaw, e4 := readPublishInput(snapshot, knowledgepublish.MaxRoleBytes)
	timestampRaw, e5 := readPublishInput(timestamp, knowledgepublish.MaxRoleBytes)
	rootRaw := make([][]byte, 0, len(successors))
	for _, path := range successors {
		raw, e := readPublishInput(path, knowledgepublish.MaxRootBytes)
		if e != nil {
			return knowledgePublishError()
		}
		rootRaw = append(rootRaw, raw)
	}
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || e5 != nil {
		return knowledgePublishError()
	}
	packageRaw, receipt, err := knowledgepublish.FinalizeRotatedPackage(knowledgepublish.RotatedFinalizePackageOptions{InitialRoot: initialRaw, InitialRootDigest: initialDigest, SuccessorRoots: rootRaw, Target: targetRaw, Targets: targetsRaw, Snapshot: snapshotRaw, Timestamp: timestampRaw})
	if err != nil || knowledgepublish.WriteExclusive(output, packageRaw) != nil {
		return knowledgePublishError()
	}
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return knowledgePublishError()
	}
	if _, err = fmt.Fprintln(stdout, string(encoded)); err != nil {
		return &commandError{code: 2, message: "knowledge-publish: receipt output failed"}
	}
	return nil
}

func runPrepareRootTransition(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("knowledge-publish prepare-root-transition", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var trusted, trustedDigest, template, templateDigest, output string
	flags.StringVar(&trusted, "trusted-root", "", "currently trusted signed public root")
	flags.StringVar(&trustedDigest, "trusted-root-digest", "", "independently verified trusted root SHA-256")
	flags.StringVar(&template, "successor-template", "", "self-signed public successor root template")
	flags.StringVar(&templateDigest, "successor-template-digest", "", "exact successor template SHA-256")
	flags.StringVar(&output, "output", "", "new private transition step directory")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			_, e := fmt.Fprintln(stdout, "usage: prufyx-maintainer knowledge-publish prepare-root-transition --trusted-root ABS --trusted-root-digest sha256:... --successor-template ABS --successor-template-digest sha256:... --output ABS")
			return e
		}
		return knowledgePublishError()
	}
	if flags.NArg() != 0 || trusted == "" || trustedDigest == "" || template == "" || templateDigest == "" || output == "" || !filepath.IsAbs(output) {
		return knowledgePublishError()
	}
	trustedRaw, e1 := readPublishInput(trusted, knowledgepublish.MaxRootBytes)
	templateRaw, e2 := readPublishInput(template, knowledgepublish.MaxRootBytes)
	p, err := knowledgepublish.PrepareRootTransition(knowledgepublish.RootTransitionOptions{TrustedRoot: trustedRaw, TrustedRootDigest: trustedDigest, SuccessorTemplate: templateRaw, SuccessorTemplateDigest: templateDigest})
	if e1 != nil || e2 != nil || err != nil || knowledgepublish.WritePreparation(output, knowledgepublish.Preparation{Role: "root", UnsignedMetadata: p.UnsignedMetadata, Payload: p.Payload, Request: p.Request}) != nil {
		return knowledgePublishError()
	}
	return nil
}

func runFinalizeRootTransition(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("knowledge-publish finalize-root-transition", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var trusted, trustedDigest, template, templateDigest, unsigned, request, output string
	var signatures []string
	flags.StringVar(&trusted, "trusted-root", "", "currently trusted signed public root")
	flags.StringVar(&trustedDigest, "trusted-root-digest", "", "independently verified trusted root SHA-256")
	flags.StringVar(&template, "successor-template", "", "self-signed public successor root template")
	flags.StringVar(&templateDigest, "successor-template-digest", "", "exact successor template SHA-256")
	flags.StringVar(&unsigned, "unsigned", "", "exact prepared unsigned successor root")
	flags.StringVar(&request, "request", "", "exact prepared root-transition request")
	flags.StringVar(&output, "output", "", "new finalized successor root")
	flags.Func("signatures", "absolute root signature contribution; repeat for each contribution", func(v string) error { signatures = append(signatures, v); return nil })
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			_, e := fmt.Fprintln(stdout, "usage: prufyx-maintainer knowledge-publish finalize-root-transition --trusted-root ABS --trusted-root-digest sha256:... --successor-template ABS --successor-template-digest sha256:... --unsigned ABS --request ABS --signatures ABS [--signatures ABS ...] --output ABS")
			return e
		}
		return knowledgePublishError()
	}
	if flags.NArg() != 0 || trusted == "" || trustedDigest == "" || template == "" || templateDigest == "" || unsigned == "" || request == "" || output == "" || len(signatures) == 0 || len(signatures) > 32 || !filepath.IsAbs(output) {
		return knowledgePublishError()
	}
	tr, e1 := readPublishInput(trusted, knowledgepublish.MaxRootBytes)
	tp, e2 := readPublishInput(template, knowledgepublish.MaxRootBytes)
	un, e3 := readPublishInput(unsigned, knowledgepublish.MaxRootBytes)
	rq, e4 := readPublishInput(request, knowledgepublish.MaxEnvelopeBytes)
	all := make([][]byte, 0, len(signatures))
	for _, path := range signatures {
		raw, e := readPublishInput(path, knowledgepublish.MaxEnvelopeBytes)
		if e != nil {
			return knowledgePublishError()
		}
		all = append(all, raw)
	}
	finalized, receipt, err := knowledgepublish.FinalizeRootTransition(knowledgepublish.RootTransitionFinalizeOptions{RootTransitionOptions: knowledgepublish.RootTransitionOptions{TrustedRoot: tr, TrustedRootDigest: trustedDigest, SuccessorTemplate: tp, SuccessorTemplateDigest: templateDigest}, UnsignedMetadata: un, Request: rq, Signatures: all})
	if e1 != nil || e2 != nil || e3 != nil || e4 != nil || err != nil || knowledgepublish.WriteExclusive(output, finalized) != nil {
		return knowledgePublishError()
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		return knowledgePublishError()
	}
	if _, err = fmt.Fprintln(stdout, string(raw)); err != nil {
		return &commandError{code: 2, message: "knowledge-publish: receipt output failed"}
	}
	return nil
}

type publishCommon struct {
	root, rootDigest, target, output string
}

func bindPublishCommon(flags *flag.FlagSet, values *publishCommon, includeTarget bool) {
	flags.StringVar(&values.root, "root", "", "independently supplied signed public TUF root")
	flags.StringVar(&values.rootDigest, "root-digest", "", "independently verified public root SHA-256")
	if includeTarget {
		flags.StringVar(&values.target, "target", "", "canonical CNCF external replacement target")
	}
	flags.StringVar(&values.output, "output", "", "new private output path")
}

func runPrepareTargets(args []string) error {
	flags := flag.NewFlagSet("knowledge-publish prepare-targets", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var common publishCommon
	var version int64
	var expires string
	bindPublishCommon(flags, &common, true)
	flags.Int64Var(&version, "version", 0, "positive targets metadata version")
	flags.StringVar(&expires, "expires", "", "targets expiry as exact UTC RFC3339")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !completeCommon(common, true) || version == 0 || expires == "" {
		return knowledgePublishError()
	}
	root, target, err := readRootTarget(common)
	if err != nil {
		return knowledgePublishError()
	}
	prepared, err := knowledgepublish.PrepareTargets(knowledgepublish.TargetsOptions{Root: root, Target: target, RootDigest: common.rootDigest, Version: version, Expires: expires})
	if err != nil || knowledgepublish.WritePreparation(common.output, prepared) != nil {
		return knowledgePublishError()
	}
	return nil
}

func runPrepareSnapshot(args []string) error {
	flags := flag.NewFlagSet("knowledge-publish prepare-snapshot", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var common publishCommon
	var targets, expires string
	var version int64
	bindPublishCommon(flags, &common, true)
	flags.StringVar(&targets, "targets", "", "finalized targets metadata")
	flags.Int64Var(&version, "version", 0, "positive snapshot metadata version")
	flags.StringVar(&expires, "expires", "", "snapshot expiry as exact UTC RFC3339")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !completeCommon(common, true) || targets == "" || version == 0 || expires == "" {
		return knowledgePublishError()
	}
	root, target, err := readRootTarget(common)
	if err != nil {
		return knowledgePublishError()
	}
	targetsRaw, err := readPublishInput(targets, knowledgepublish.MaxRoleBytes)
	if err != nil {
		return knowledgePublishError()
	}
	prepared, err := knowledgepublish.PrepareSnapshot(knowledgepublish.SnapshotOptions{Root: root, Target: target, Targets: targetsRaw, RootDigest: common.rootDigest, Version: version, Expires: expires})
	if err != nil || knowledgepublish.WritePreparation(common.output, prepared) != nil {
		return knowledgePublishError()
	}
	return nil
}

func runPrepareTimestamp(args []string) error {
	flags := flag.NewFlagSet("knowledge-publish prepare-timestamp", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var common publishCommon
	var targets, snapshot, expires string
	var version int64
	bindPublishCommon(flags, &common, true)
	flags.StringVar(&targets, "targets", "", "finalized targets metadata")
	flags.StringVar(&snapshot, "snapshot", "", "finalized snapshot metadata")
	flags.Int64Var(&version, "version", 0, "positive timestamp metadata version")
	flags.StringVar(&expires, "expires", "", "timestamp expiry as exact UTC RFC3339")
	if flags.Parse(args) != nil || flags.NArg() != 0 || !completeCommon(common, true) || targets == "" || snapshot == "" || version == 0 || expires == "" {
		return knowledgePublishError()
	}
	root, target, err := readRootTarget(common)
	if err != nil {
		return knowledgePublishError()
	}
	targetsRaw, err1 := readPublishInput(targets, knowledgepublish.MaxRoleBytes)
	snapshotRaw, err2 := readPublishInput(snapshot, knowledgepublish.MaxRoleBytes)
	if err1 != nil || err2 != nil {
		return knowledgePublishError()
	}
	prepared, err := knowledgepublish.PrepareTimestamp(knowledgepublish.TimestampOptions{Root: root, Target: target, Targets: targetsRaw, Snapshot: snapshotRaw, RootDigest: common.rootDigest, Version: version, Expires: expires})
	if err != nil || knowledgepublish.WritePreparation(common.output, prepared) != nil {
		return knowledgePublishError()
	}
	return nil
}

func runFinalizeRole(args []string) error {
	flags := flag.NewFlagSet("knowledge-publish finalize-role", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var root, rootDigest, role, unsigned, signatures, output string
	flags.StringVar(&root, "root", "", "independently supplied signed public TUF root")
	flags.StringVar(&rootDigest, "root-digest", "", "independently verified public root SHA-256")
	flags.StringVar(&role, "role", "", "targets, snapshot, or timestamp")
	flags.StringVar(&unsigned, "unsigned", "", "prepared unsigned metadata")
	flags.StringVar(&signatures, "signatures", "", "external signature envelope")
	flags.StringVar(&output, "output", "", "new finalized metadata file")
	if flags.Parse(args) != nil || flags.NArg() != 0 || root == "" || rootDigest == "" || unsigned == "" || signatures == "" || output == "" {
		return knowledgePublishError()
	}
	rootRaw, err1 := readPublishInput(root, knowledgepublish.MaxRootBytes)
	unsignedRaw, err2 := readPublishInput(unsigned, knowledgepublish.MaxRoleBytes)
	signatureRaw, err3 := readPublishInput(signatures, knowledgepublish.MaxEnvelopeBytes)
	if err1 != nil || err2 != nil || err3 != nil {
		return knowledgePublishError()
	}
	finalized, err := knowledgepublish.FinalizeRole(rootRaw, rootDigest, role, unsignedRaw, signatureRaw)
	if err != nil || knowledgepublish.WriteExclusive(output, finalized) != nil {
		return knowledgePublishError()
	}
	return nil
}

func runFinalizeKnowledgePackage(args []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("knowledge-publish finalize-package", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var common publishCommon
	var targets, snapshot, timestamp, packageURL, releasePlanOutput string
	bindPublishCommon(flags, &common, true)
	flags.StringVar(&targets, "targets", "", "finalized targets metadata")
	flags.StringVar(&snapshot, "snapshot", "", "finalized snapshot metadata")
	flags.StringVar(&timestamp, "timestamp", "", "finalized timestamp metadata")
	flags.StringVar(&packageURL, "package-url", "", "exact HTTPS URL for the complete package")
	flags.StringVar(&releasePlanOutput, "release-plan-output", "", "new local release plan file")
	if flags.Parse(args) != nil {
		return knowledgePublishError()
	}
	planRequested := packageURL != "" || releasePlanOutput != ""
	if flags.NArg() != 0 || !completeCommon(common, true) || targets == "" || snapshot == "" || timestamp == "" ||
		(packageURL == "") != (releasePlanOutput == "") || planRequested && (!filepath.IsAbs(releasePlanOutput) || filepath.Clean(releasePlanOutput) == filepath.Clean(common.output)) {
		return knowledgePublishError()
	}
	root, target, err := readRootTarget(common)
	if err != nil {
		return knowledgePublishError()
	}
	targetsRaw, err1 := readPublishInput(targets, knowledgepublish.MaxRoleBytes)
	snapshotRaw, err2 := readPublishInput(snapshot, knowledgepublish.MaxRoleBytes)
	timestampRaw, err3 := readPublishInput(timestamp, knowledgepublish.MaxRoleBytes)
	if err1 != nil || err2 != nil || err3 != nil {
		return knowledgePublishError()
	}
	opts := knowledgepublish.FinalizePackageOptions{Root: root, Target: target, Targets: targetsRaw, Snapshot: snapshotRaw, Timestamp: timestampRaw, RootDigest: common.rootDigest}
	var packageRaw, planRaw []byte
	var receipt knowledgepublish.FinalizationReceipt
	if planRequested {
		packageRaw, planRaw, receipt, err = knowledgepublish.FinalizePackageWithReleasePlan(opts, packageURL)
	} else {
		packageRaw, receipt, err = knowledgepublish.FinalizePackage(opts)
	}
	if err != nil || writePackageAndPlan(common.output, packageRaw, releasePlanOutput, planRaw) != nil {
		return knowledgePublishError()
	}
	receiptRaw, err := json.Marshal(receipt)
	if err != nil {
		return knowledgePublishError()
	}
	if _, err := fmt.Fprintln(stdout, string(receiptRaw)); err != nil {
		return &commandError{code: 2, message: "knowledge-publish: receipt output failed"}
	}
	return nil
}

func writePackageAndPlan(packagePath string, packageRaw []byte, planPath string, planRaw []byte) error {
	if err := knowledgepublish.WriteExclusive(packagePath, packageRaw); err != nil {
		return err
	}
	// Publication is deliberately ordered, not crash-atomic. The already
	// durable package remains if the plan output cannot be created.
	if planPath != "" {
		return knowledgepublish.WriteExclusive(planPath, planRaw)
	}
	return nil
}

func completeCommon(values publishCommon, target bool) bool {
	return values.root != "" && values.rootDigest != "" && values.output != "" && (!target || values.target != "") && filepath.IsAbs(values.output)
}

func readRootTarget(values publishCommon) ([]byte, []byte, error) {
	root, err := readPublishInput(values.root, knowledgepublish.MaxRootBytes)
	if err != nil {
		return nil, nil, err
	}
	target, err := readPublishInput(values.target, knowledgepublish.MaxTargetBytes)
	return root, target, err
}

func readPublishInput(path string, limit int) ([]byte, error) {
	if !filepath.IsAbs(path) {
		return nil, knowledgepublish.ErrRejected
	}
	return currentbundle.ReadBoundedFile(path, limit)
}

func knowledgePublishError() error {
	return &commandError{code: 2, message: "knowledge-publish: operation rejected"}
}
