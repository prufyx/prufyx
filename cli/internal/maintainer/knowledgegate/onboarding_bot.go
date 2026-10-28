// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sort"
	"time"
)

// The onboarding-bot tier: a second key tier in the owner-signed key file.
// Its signature is accepted for one thing, an onboarding batch whose
// projects are all kind new, inside the caps below. Every other path (rule,
// record and baseline approvals, knowledge batches, the signing commands for
// them) refuses a key that is not an owner key.
const (
	// MaxBotOnboardingProjects bounds the projects of one bot-signed batch.
	MaxBotOnboardingProjects = 50
	// MaxBotBatchesWeek and MaxBotProjectsWeek bound the bot-signed batches
	// and their projects inside BotOnboardingWindow, this one included.
	MaxBotBatchesWeek  = 3
	MaxBotProjectsWeek = 100
	// BotOnboardingWindow is the span the weekly caps count over.
	BotOnboardingWindow = 7 * 24 * time.Hour
)

// checkOnboardingTier binds the record's identity to the key's tier.
func checkOnboardingTier(key ApprovalKey, keys ApprovalKeys, r OnboardingRecord) error {
	switch {
	case key.ownerTier():
		if keys.isBot(r.Identity) {
			return fmt.Errorf("onboarding batch: %s is a bot identity and cannot sign with an owner key", r.Identity)
		}
		if !keys.isOwner(r.Identity) {
			return fmt.Errorf("onboarding batch: %s is not an owner", r.Identity)
		}
	case key.botTier():
		if keys.isOwner(r.Identity) {
			return fmt.Errorf("onboarding batch: %s is an owner identity and cannot sign with a bot-tier key", r.Identity)
		}
		if !keys.isBot(r.Identity) {
			return fmt.Errorf("onboarding batch: %s is not a pinned bot", r.Identity)
		}
		if len(r.Projects) > MaxBotOnboardingProjects {
			return fmt.Errorf("onboarding batch: a bot-tier batch holds at most %d projects, this one %d", MaxBotOnboardingProjects, len(r.Projects))
		}
		for _, p := range r.Projects {
			if p.Kind != OnboardingKindNew {
				return fmt.Errorf("onboarding batch: a bot-tier batch may hold kind new projects only (%s is %s)", logSafe(p.Slug), logSafe(p.Kind))
			}
		}
	default:
		return errors.New("onboarding batch: the signing key has an unknown tier")
	}
	return nil
}

// ownerOnboarding reports whether a batch of the base was decided by an
// owner: an owner identity under a key that is still pinned as an owner key
// or no longer pinned. Everything else counts as a bot batch (fail closed).
func ownerOnboarding(env OnboardingEnvelope, keys ApprovalKeys) bool {
	if !keys.isOwner(env.Record.Identity) {
		return false
	}
	if k := keys.keyByID(env.KeyID); k != nil && !k.ownerTier() {
		return false
	}
	return true
}

// botOnboardingLimits is the gate's bot-tier rule (O8b, O8c), run once the
// signature verified; it returns "" for a batch signed with an owner key.
// A bot-tier batch is refused while the bot signer is paused, and when it
// would take the bot batches of the base still inside the window above
// MaxBotBatchesWeek, or their projects above MaxBotProjectsWeek.
//
// The base batches are counted by notAfter, not decidedAt: decidedAt is the
// signer's to set up to 72 hours back, notAfter always lies after the time
// the batch was admitted. A batch file stays in the tree until
// OnboardingRetention after its notAfter (onboardingPathReason), so every
// batch inside the window is in baseFiles. A file whose time cannot be read
// is counted.
func botOnboardingLimits(env OnboardingEnvelope, keys ApprovalKeys, baseFiles map[string][]byte, now time.Time, paused bool) string {
	key := keys.keyByID(env.KeyID)
	if key == nil || !key.botTier() {
		return ""
	}
	if paused {
		return "O8b: the bot signer is paused (KNOWLEDGE_BOT_SIGNER_PAUSED): no bot-tier batch is admitted"
	}
	names := make([]string, 0, len(baseFiles))
	for n := range baseFiles {
		names = append(names, n)
	}
	sort.Strings(names)
	since := now.UTC().Add(-BotOnboardingWindow)
	batches, projects := 1, len(env.Record.Projects)
	for _, n := range names {
		b, err := decodeOnboarding(baseFiles[n])
		if err != nil || ownerOnboarding(b, keys) {
			continue
		}
		if until, err := time.Parse(time.RFC3339, b.Record.NotAfter); err == nil && until.Before(since) {
			continue
		}
		batches++
		projects += len(b.Record.Projects)
	}
	switch {
	case batches > MaxBotBatchesWeek:
		return fmt.Sprintf("O8c: this would be bot-tier batch %d inside 7 days, at most %d are admitted", batches, MaxBotBatchesWeek)
	case projects > MaxBotProjectsWeek:
		return fmt.Sprintf("O8c: this would bring the bot-tier projects inside 7 days to %d, at most %d are admitted", projects, MaxBotProjectsWeek)
	}
	return ""
}

// checkOnboardingSigner refuses a key that is not pinned or has expired at
// now, and an identity that does not belong to the key's tier; it returns the
// key id. The signing command runs it before it asks for the confirmation.
func checkOnboardingSigner(keys ApprovalKeys, key ed25519.PrivateKey, identity string, now time.Time) (string, error) {
	keyID := ApprovalKeyID(key.Public().(ed25519.PublicKey))
	pinned := keys.keyByID(keyID)
	if pinned == nil {
		return "", fmt.Errorf("the signing key %s is not pinned in the approval key file", keyID)
	}
	if notAfter, err := time.Parse(time.RFC3339, pinned.NotAfter); err != nil || !now.Before(notAfter) {
		return "", fmt.Errorf("the signing key %s expired at %s", keyID, pinned.NotAfter)
	}
	if err := checkOnboardingTier(*pinned, keys, OnboardingRecord{Identity: identity}); err != nil {
		return "", err
	}
	return keyID, nil
}
