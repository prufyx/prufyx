// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"errors"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfknowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgeauto"
)

// autoOpenStore verifies the default store. Test seam.
var autoOpenStore = knowledge.OpenSelectedCNCF

// cncfEmbeddedOnlyFlags select check modes that have no external-knowledge
// form; they are never given an automatic knowledge source.
var cncfEmbeddedOnlyFlags = []string{
	"config-map", "resource-exclusions-config-map", "repository-secret", "linkerd-resource",
	"karmada-resource", "cilium-policy", "keadm-init-argv", "tekton-config-observability",
}

// autoClock is the time of an automatic (not explicit) evaluation by the
// embedded knowledge. Test seam.
var autoClock = time.Now

// autoCompare compares a verified store selection with the embedded pack, and
// autoExpiredRoot reads the initial trust root of a store whose signed
// metadata expired. Test seams.
var (
	autoCompare     = cncfknowledge.CompareSelection
	autoExpiredRoot = knowledge.ExpiredStoreRootDigest
)

// resolveCNCFKnowledge picks the knowledge source of a check that has no
// explicit one. It only acts when the command line names neither
// --knowledge-db, --now, a replay, nor a knowledge pin: an explicit database
// always wins and --now (the embedded, replayable form) is never changed.
//
//   - --knowledge=embedded: embedded knowledge at the current time.
//   - otherwise a default store that verifies (and has the pinned root when
//     the build pins one) is compared with the embedded knowledge by the
//     latest evidence review date; the newer one is used (on a tie the
//     embedded, unless the store's content differs). A chosen store is
//     selected through knowledgeDB;
//   - a default store whose signed metadata has expired (and nothing else)
//     is not used: the embedded knowledge is, with a warning;
//   - any other default store that is present but unusable is refused
//     (stop=true);
//   - no default store: embedded knowledge at the current time.
//
// The chosen source is recorded in r.knowledgeSource and written to
// standard error; the report bytes are not changed.
func (r *runtime) resolveCNCFKnowledge(args []string, mode, project string, knowledgeDB, knowledgeRevision, knowledgeBundleDigest, knowledgeTrustReceiptDigest, nowText *string, replay string) (code int, stop bool) {
	if mode != "" && mode != knowledgeauto.ModeAuto && mode != knowledgeauto.ModeEmbedded {
		return r.usage("invalid --knowledge; use auto or embedded"), true
	}
	if mode == knowledgeauto.ModeEmbedded && flagProvided(args, "knowledge-db") {
		return r.usage("--knowledge=embedded cannot be used with --knowledge-db"), true
	}
	// Routes that read the embedded knowledge only keep requiring --now.
	if anyFlagProvided(args, cncfEmbeddedOnlyFlags...) || anyFlagProvided(args, cncfCustomResourceFlags...) {
		return 0, false
	}
	if flagProvided(args, "now") || flagProvided(args, "knowledge-db") || replay != "" ||
		anyFlagProvided(args, "knowledge-revision", "knowledge-bundle-digest", "knowledge-trust-receipt-digest") {
		return 0, false
	}
	embeddedWith := func(prefix, why string) {
		*nowText = autoClock().UTC().Truncate(time.Second).Format(time.RFC3339)
		r.knowledgeSource = fmt.Sprintf("embedded (%s)", why)
		fmt.Fprintf(r.stderr, "prufyx: %sknowledge source: embedded, %s\n", prefix, why)
	}
	embedded := func(why string) { embeddedWith("", why) }
	if mode == knowledgeauto.ModeEmbedded {
		embedded("forced by --knowledge=embedded")
		return 0, false
	}
	root, present, err := knowledgeauto.Locate()
	if err == nil && !present {
		embedded("no local knowledge database installed")
		return 0, false
	}
	if err != nil {
		return r.fail(err.Error(), ExitIntegrity), true
	}
	selected, err := autoOpenStore(knowledge.SelectionRequest{StoreRoot: root}, []string{project})
	if fallback, ok := knowledgeauto.FallbackReason(err); err != nil && ok {
		// Expired signed metadata is not tampering: the embedded knowledge
		// is used, loudly. The pin still has to match.
		rootDigest, rerr := autoExpiredRoot(root)
		if rerr == nil {
			rerr = knowledgeauto.CheckPin(pinnedRootDigest(knowledgeauto.Profile), rootDigest)
		}
		if rerr == nil {
			embeddedWith("warning: ", knowledgeauto.FallbackWhy(fallback))
			return 0, false
		}
		err = rerr
	}
	if err == nil && (!selected.Valid() || selected.Mode() != knowledge.SelectionCurrent || !selected.PerProject()) {
		err = knowledge.ErrIntegrity
	}
	if err == nil {
		err = knowledgeauto.CheckPin(pinnedRootDigest(knowledgeauto.Profile), selected.TrustReceipt().InitialRootDigest)
	}
	if err != nil {
		var refused *knowledgeauto.Refused
		if !errors.As(err, &refused) {
			err = &knowledgeauto.Refused{Reason: knowledgeauto.Reason(err)}
		}
		return r.fail(err.Error(), ExitIntegrity), true
	}
	cmp, err := autoCompare(selected, []string{project})
	if err != nil {
		return r.fail((&knowledgeauto.Refused{Reason: "verification failed"}).Error(), ExitIntegrity), true
	}
	choice := knowledgeauto.Choose(cmp.StoreEvidenceAt, cmp.EmbeddedEvidenceAt, cmp.Identical, cmp.StaleProject)
	if !choice.UseStore() {
		embedded(choice.EmbeddedWhy())
		return 0, false
	}
	// Bind the evaluation to what was just verified and pin-checked: the
	// store is opened again by the explicit path, and that open refuses any
	// other revision, bundle or trust receipt (which commits to the initial
	// root, so the pin carries over). A store swapped or advanced in between
	// is an integrity failure, never evaluated.
	*knowledgeDB = root
	*knowledgeRevision, *knowledgeBundleDigest, *knowledgeTrustReceiptDigest = selected.Revision(), selected.BundleDigest(), selected.TrustReceiptDigest()
	r.knowledgeSource = fmt.Sprintf("local-db (revision %s, bundle digest %s)", selected.Revision(), selected.BundleDigest())
	fmt.Fprintf(r.stderr, "prufyx: knowledge source: local-db, revision %s, bundle digest %s (%s)\n", selected.Revision(), selected.BundleDigest(), choice.StoreDetail())
	receipt := selected.TrustReceipt()
	fmt.Fprintf(r.stderr, "prufyx: note: %s\n", knowledgeauto.StalenessNote(receipt.VerifiedAt, receipt.EvidenceExpiresAt))
	return 0, false
}
