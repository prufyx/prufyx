// SPDX-License-Identifier: AGPL-3.0-only

package evidencereattest

import (
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/evidencerepin"
)

// mirrorRepos marks every repository of the worklist as read from a mirror
// with the given last-check and releases times.
func mirrorRepos(wl *evidencerepin.Worklist, checkedAt, releasesAt string) {
	for i := range wl.Repos {
		wl.Repos[i].Source = evidencerepin.SourceMirror
		wl.Repos[i].MirrorCheckedAt = checkedAt
		wl.Repos[i].MirrorReleasesAt = releasesAt
	}
}

func TestPrepareMirrorWorklistUsesTheMirrorsTime(t *testing.T) {
	packPath := "/p/rules.json"
	fresh := rfc3339(baseNow.Add(-time.Hour))
	old := rfc3339(baseNow.Add(-100 * time.Hour))

	t.Run("fresh mirror evidence is eligible", func(t *testing.T) {
		wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
		mirrorRepos(&wl, fresh, fresh)
		result := prepareSingle(t, wl, pack, packPath)
		if len(result.Statement.Rules) != 1 {
			t.Fatalf("a fresh mirror worklist must still be eligible: %+v", result.Statement.NotExtended)
		}
	})
	// The run was recent (resolvedAt is fresh) but the mirror was not: the
	// mirror's own time decides.
	t.Run("an old last check makes it stale", func(t *testing.T) {
		wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
		mirrorRepos(&wl, old, fresh)
		assertOnlyExclusion(t, prepareSingle(t, wl, pack, packPath), "rule-a", reasonStaleBaseline)
	})
	t.Run("old release metadata makes it stale", func(t *testing.T) {
		wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
		mirrorRepos(&wl, fresh, old)
		assertOnlyExclusion(t, prepareSingle(t, wl, pack, packPath), "rule-a", reasonStaleBaseline)
	})
	t.Run("a missing mirror time is stale, never fresh", func(t *testing.T) {
		wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
		mirrorRepos(&wl, "", fresh)
		assertOnlyExclusion(t, prepareSingle(t, wl, pack, packPath), "rule-a", reasonStaleBaseline)
		wl, pack = buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
		mirrorRepos(&wl, fresh, "not a time")
		assertOnlyExclusion(t, prepareSingle(t, wl, pack, packPath), "rule-a", reasonStaleBaseline)
	})
	t.Run("an unknown source is stale", func(t *testing.T) {
		wl, pack := buildWorklistAndPack(t, packPath, baseNow, []ruleSpec{freshSpec("rule-a", "proj-a", baseNow)})
		wl.Repos[0].Source = "somewhere-else"
		assertOnlyExclusion(t, prepareSingle(t, wl, pack, packPath), "rule-a", reasonStaleBaseline)
	})
}

func TestEvidenceAtOfLineResolution(t *testing.T) {
	fresh := rfc3339(baseNow.Add(-time.Hour))
	old := rfc3339(baseNow.Add(-100 * time.Hour))
	line := evidencerepin.LineResolution{ResolvedAt: fresh, Source: evidencerepin.SourceMirror, MirrorCheckedAt: old, MirrorReleasesAt: fresh}
	at, ok := line.EvidenceAt()
	if !ok || rfc3339(at) != old {
		t.Fatalf("a line must be as old as the mirror's last check: %v %v", at, ok)
	}
	line.MirrorCheckedAt = ""
	if _, ok := line.EvidenceAt(); ok {
		t.Fatal("a mirror line without the mirror's time must not be fresh")
	}
}
