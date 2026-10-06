// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"errors"
	"fmt"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
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

// resolveCNCFKnowledge picks the knowledge source of a check that has no
// explicit one. It only acts when the command line names neither
// --knowledge-db, --now, a replay, nor a knowledge pin: an explicit database
// always wins and --now (the embedded, replayable form) is never changed.
//
//   - --knowledge=embedded: embedded knowledge at the current time.
//   - otherwise a default store that verifies (and has the pinned root when
//     the build pins one) is selected through knowledgeDB;
//   - a default store that is present but unusable is refused (stop=true);
//   - no default store: embedded knowledge at the current time.
//
// The chosen source is recorded in r.knowledgeSource and written to
// standard error; the report bytes are not changed.
func (r *runtime) resolveCNCFKnowledge(args []string, mode, project string, knowledgeDB, nowText *string, replay string) (code int, stop bool) {
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
	embedded := func(why string) {
		*nowText = autoClock().UTC().Truncate(time.Second).Format(time.RFC3339)
		r.knowledgeSource = fmt.Sprintf("embedded (%s)", why)
		fmt.Fprintf(r.stderr, "prufyx: knowledge source: embedded, %s\n", why)
	}
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
	if err == nil && (!selected.Valid() || selected.Mode() != knowledge.SelectionCurrent) {
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
	*knowledgeDB = root
	r.knowledgeSource = fmt.Sprintf("local-db (revision %s, bundle digest %s)", selected.Revision(), selected.BundleDigest())
	embeddedRevision := "unknown"
	if catalog, cerr := cncfcheck.Catalog(false, project); cerr == nil {
		embeddedRevision = catalog.KnowledgeRevision
	}
	fmt.Fprintf(r.stderr, "prufyx: knowledge source: local-db, revision %s, bundle digest %s (embedded would be %s; the verified local database is preferred)\n", selected.Revision(), selected.BundleDigest(), embeddedRevision)
	return 0, false
}
