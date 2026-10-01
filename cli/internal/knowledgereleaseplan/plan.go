// SPDX-License-Identifier: AGPL-3.0-only

// Package knowledgereleaseplan defines the bounded unsigned routing and
// assertion file used by an explicit local knowledge update.
package knowledgereleaseplan

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgefetch"
)

const (
	Schema    = "prufyx.io/knowledge-release-plan/v1"
	Authority = "UNSIGNED_ROUTING_AND_ASSERTIONS_NOT_TRUST"
	RootMode  = "SINGLE_ROOT_NO_ROTATION_V1"
	MaxBytes  = 32 << 10
	maxDepth  = 12
	maxItems  = 64
)

var ErrRejected = errors.New("knowledge release plan rejected")

type Plan struct {
	Schema                string                `json:"schema"`
	Authority             string                `json:"authority"`
	Profile               string                `json:"profile"`
	Package               Package               `json:"package"`
	Target                Target                `json:"target"`
	PublisherVerification PublisherVerification `json:"publisherVerification"`
}

type Package struct {
	URL    string `json:"url"`
	Digest string `json:"digest"`
}

type Target struct {
	Path                   string `json:"path"`
	Revision               string `json:"revision"`
	Digest                 string `json:"digest"`
	Purpose                string `json:"purpose"`
	EngineCapabilityDigest string `json:"engineCapabilityDigest"`
}

type PublisherVerification struct {
	Mode                       string                       `json:"mode"`
	PublisherInitialRootDigest string                       `json:"publisherInitialRootDigest"`
	RootHistory                []knowledge.RootHistoryEntry `json:"rootHistory"`
	Root                       knowledge.RoleReceipt        `json:"root"`
	Timestamp                  knowledge.RoleReceipt        `json:"timestamp"`
	Snapshot                   knowledge.RoleReceipt        `json:"snapshot"`
	Targets                    knowledge.RoleReceipt        `json:"targets"`
}

func Read(path string) (Plan, error) {
	raw, info, err := currentbundle.ReadBoundedFileInfo(path, MaxBytes)
	if err != nil || info == nil || !info.Mode().IsRegular() {
		return Plan{}, ErrRejected
	}
	return Parse(raw)
}

func Parse(raw []byte) (Plan, error) {
	if len(raw) == 0 || len(raw) > MaxBytes || !utf8.Valid(raw) || validateJSON(raw) != nil {
		return Plan{}, ErrRejected
	}
	var plan Plan
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&plan) != nil {
		return Plan{}, ErrRejected
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Plan{}, ErrRejected
	}
	canonical, err := json.Marshal(plan)
	if err != nil || !bytes.Equal(raw, canonical) || validate(plan) != nil {
		return Plan{}, ErrRejected
	}
	return plan, nil
}

func Marshal(plan Plan) ([]byte, error) {
	if validate(plan) != nil {
		return nil, ErrRejected
	}
	raw, err := json.Marshal(plan)
	if err != nil || len(raw) > MaxBytes {
		return nil, ErrRejected
	}
	return raw, nil
}

func (p Plan) VerificationAssertions() knowledge.VerificationAssertions {
	return knowledge.VerificationAssertions{
		PublisherInitialRootDigest: p.PublisherVerification.PublisherInitialRootDigest,
		RootHistory:                append([]knowledge.RootHistoryEntry(nil), p.PublisherVerification.RootHistory...),
		Root:                       p.PublisherVerification.Root,
		Timestamp:                  p.PublisherVerification.Timestamp,
		Snapshot:                   p.PublisherVerification.Snapshot,
		Targets:                    p.PublisherVerification.Targets,
		TargetPath:                 p.Target.Path,
		Purpose:                    p.Target.Purpose,
		EngineCapabilityDigest:     p.Target.EngineCapabilityDigest,
	}
}

// VerificationAssertionsDigest returns the recovery and receipt identity for
// the plan's verified-material assertions. It does not authenticate the plan.
func (p Plan) VerificationAssertionsDigest() (string, error) {
	return knowledge.VerificationAssertionsDigest(p.VerificationAssertions())
}

func validate(plan Plan) error {
	if plan.Schema != Schema || plan.Authority != Authority || plan.Profile != "cncf" ||
		plan.PublisherVerification.Mode != RootMode ||
		knowledgefetch.ValidateSource(plan.Package.URL) != nil ||
		plan.Target.Path != knowledge.ConstraintsTargetPath || plan.Target.Purpose != "operator_provided" ||
		len(plan.PublisherVerification.RootHistory) != 1 {
		return ErrRejected
	}
	history := plan.PublisherVerification.RootHistory[0]
	if history.Digest != plan.PublisherVerification.PublisherInitialRootDigest ||
		history.Version != plan.PublisherVerification.Root.Version ||
		history.Digest != plan.PublisherVerification.Root.Digest {
		return ErrRejected
	}
	for _, role := range []knowledge.RoleReceipt{plan.PublisherVerification.Root, plan.PublisherVerification.Timestamp, plan.PublisherVerification.Snapshot, plan.PublisherVerification.Targets} {
		if role.Version < 1 || parseUTC(role.Expires) != nil {
			return ErrRejected
		}
	}
	assertions := plan.VerificationAssertions()
	if err := knowledge.ValidateImportAssertions(knowledge.ImportRequest{
		ExpectedPackageDigest: plan.Package.Digest,
		ExpectedRevision:      plan.Target.Revision,
		ExpectedBundleDigest:  plan.Target.Digest,
		ExpectedVerification:  &assertions,
	}); err != nil {
		return ErrRejected
	}
	return nil
}

func parseUTC(value string) error {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339) != value {
		return ErrRejected
	}
	return nil
}

func validateJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consume(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrRejected
	}
	return nil
}

func consume(decoder *json.Decoder, depth int) error {
	if depth > maxDepth {
		return ErrRejected
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for count := 0; decoder.More(); count++ {
			if count >= maxItems {
				return ErrRejected
			}
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return ErrRejected
			}
			seen[key] = true
			if err := consume(decoder, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for count := 0; decoder.More(); count++ {
			if count >= maxItems || consume(decoder, depth+1) != nil {
				return ErrRejected
			}
		}
	default:
		return ErrRejected
	}
	closing, err := decoder.Token()
	if err != nil || delimiter == '{' && closing != json.Delim('}') || delimiter == '[' && closing != json.Delim(']') {
		return ErrRejected
	}
	return nil
}
