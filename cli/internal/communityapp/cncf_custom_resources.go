// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"encoding/json"
	"fmt"
	"regexp"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/cncfprepare"
)

// cncfCustomResourceFlags are the flags of the custom-resource version mode.
var cncfCustomResourceFlags = []string{"custom-resources", "custom-resources-digest", "custom-resources-complete"}

// customResourceRequest is one custom-resource version check as the
// command line gives it.
type customResourceRequest struct {
	project, path, pin        string
	complete                  bool
	from, to, nowText         string
	externalKnowledge         bool
	revision, bundle, receipt string
	replayPath, format        string
	args                      []string
}

var customResourceDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// cncfCustomResourceCheck reads one file of rendered manifests, declares
// the project's custom-resource version set from it and evaluates the
// project's rules over that set only: rules about other evidence are
// neither run nor reported. Only embedded knowledge is read.
func (r runtime) cncfCustomResourceCheck(req customResourceRequest) int {
	fact, ok := cncfprepare.CustomResourceVersionsFact(req.project)
	if !ok {
		return r.usage("custom-resource flags require a project with a custom-resource version set (argo-cd, istio or strimzi); use --help")
	}
	if req.path == "" || req.from == "" || req.to == "" || cncfUnexpectedModeFlag(req.args, cncfCustomResourceFlags...) || (flagProvided(req.args, "custom-resources-digest") && !customResourceDigestRE.MatchString(req.pin)) {
		return r.usage("invalid custom-resource check arguments; use --help")
	}
	if req.externalKnowledge || req.replayPath != "" || req.revision != "" || req.bundle != "" || req.receipt != "" {
		return r.usage("custom-resource checks read embedded knowledge only: use --now, without --knowledge-db or --replay-report")
	}
	if req.nowText == "" {
		return r.usage("custom-resource checks require canonical --now")
	}
	now, err := parseUTC(req.nowText)
	if err != nil || now.Nanosecond() != 0 || now.Format(time.RFC3339) != req.nowText {
		return r.usage("CNCF check time must be explicit canonical UTC with whole seconds")
	}
	raw, err := readCNCFPrivate(req.path, 1<<20)
	if err != nil {
		return r.fail(withPermissionHint("CUSTOM_RESOURCE_INPUT_INVALID", err), ExitUsage)
	}
	digest := digestCommunityBytes(raw)
	if req.pin != "" && req.pin != digest {
		return r.fail("CUSTOM_RESOURCE_INPUT_INTEGRITY_FAILURE", ExitIntegrity)
	}
	prepared, err := cncfprepare.PrepareCustomResourceVersionsBytes(raw, req.project, req.from, req.to, req.complete)
	if err != nil || prepared.SourceDigest != digest || prepared.InputDigest != digestCommunityBytes(prepared.CanonicalInputJSON) || !json.Valid(prepared.CanonicalInputJSON) {
		return r.fail("CUSTOM_RESOURCE_INPUT_INVALID", ExitUsage)
	}
	report, err := r.cncfChecker().CheckFacts(req.project, []string{fact}, prepared.CanonicalInputJSON, now)
	if err != nil {
		return r.cncfError("CNCF source-constraint check failed", err)
	}
	encoded, err := cncfcheck.MarshalReport(report)
	if err != nil {
		return r.fail("CNCF report integrity failure", ExitIntegrity)
	}
	if req.format == "json" {
		if _, err := fmt.Fprintln(r.stdout, string(encoded)); err != nil {
			return ExitIntegrity
		}
		return cncfcheck.ClaimExit(report)
	}
	if _, err := fmt.Fprintf(r.stdout, "%s custom-resource version review\nraw input digest: %s\nprepared input digest: %s\ncustom-resource set: %s\n", req.project, digest, prepared.InputDigest, customResourceSetLine(prepared.Reason)); err != nil {
		return ExitIntegrity
	}
	if err := writeBasisHeadline(r.stdout, report.Check.Claims, report.TrustPolicy); err != nil {
		return ExitIntegrity
	}
	summary := summarizeClaims(report.Check.Claims, flagProvided(req.args, "show-passes"))
	if summary.allUnreviewed {
		if err := writeUnreviewedTransition(r.stdout, req.project, req.from, req.to); err != nil {
			return ExitIntegrity
		}
	}
	if err := writeNativeClaims(r.stdout, summary, report.Check.Claims); err != nil {
		return ExitIntegrity
	}
	if len(report.Check.Claims) == 0 {
		if _, err := fmt.Fprintf(r.stdout, "no published rule reads the %s custom-resource version set for %s -> %s; the result stays UNKNOWN\n", req.project, req.from, req.to); err != nil {
			return ExitIntegrity
		}
	}
	if _, err := fmt.Fprintln(r.stdout, "scope: custom-resource versions the target release no longer serves; other changes, stored objects and conversion are not checked\naggregate: UNKNOWN (whole-upgrade compatibility: UNKNOWN; network used: false)"); err != nil {
		return ExitIntegrity
	}
	if err := writeSourceFooter(r.stdout, summary.shown); err != nil {
		return ExitIntegrity
	}
	return cncfcheck.ClaimExit(report)
}

// customResourceSetLine says in words how complete the declared set is.
func customResourceSetLine(reason string) string {
	switch reason {
	case cncfprepare.ReasonCustomResourcesComplete:
		return "complete"
	case cncfprepare.ReasonCustomResourcesScopeIncomplete:
		return "not complete (the manifests are not declared to be the complete set you apply; use --custom-resources-complete)"
	case cncfprepare.ReasonCustomResourcesUnattributed:
		return "not complete (objects of a custom-resource group that no reviewed project owns are present)"
	case cncfprepare.ReasonCustomResourcesPaginated:
		return "not complete (a list is paginated)"
	case cncfprepare.ReasonCustomResourcesMemberInvalid:
		return "not complete (an apiVersion is too long to record)"
	case cncfprepare.ReasonCustomResourcesTooMany:
		return "not declared (too many custom-resource versions)"
	case cncfprepare.ReasonCustomResourcesRendering:
		return "not declared (a document contains unrendered templates or cannot be parsed)"
	}
	return "not declared (the manifests cannot be read as one apply set)"
}
