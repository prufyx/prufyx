// SPDX-License-Identifier: AGPL-3.0-only

package crdversions

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"gopkg.in/yaml.v3"
)

// literalKustomizationContext is the source-consumption proof needed before
// the Redis literal comment exception can be used. Callers must derive every
// field from the pinned source tree; this helper accepts no inferred context.
type literalKustomizationContext struct {
	Project        string
	Repo           string
	Tag            string
	Commit         string
	Path           string
	MakefileSHA256 string
	DefaultSHA256  string
	Referrers      []literalKustomizationReferrer
}

type literalKustomizationReferrer struct {
	Path string
	Kind string
}

type literalKustomizationPin struct {
	Tag           string
	Commit        string
	Kustomization string
	Makefile      string
	Default       string
}

const (
	literalKustomizationProject = "redis-operator"
	literalKustomizationRepo    = "github.com/ot-container-kit/redis-operator"
	literalKustomizationPath    = "config/rbac/kustomization.yaml"
	literalKustomizationAction  = "{{ .ProjectName }}"
)

var literalKustomizationPins = []literalKustomizationPin{
	{"v0.23.0", "ce3ffdb7ed430dc86d2208385d9516d7c19d52ba", "d1fc9ce460376c0c327c50f75e548aad6b9834ee83962afdcaa4ee4ab4e386d7", "7e1e85d6a5ec9a89e289222954a1b3313ffc9872824247e6e04f29a53ca0e159", "5a23c4050bd4444f1a3565b669c8e23ce820078e8bfbe03e37529230009b1602"},
	{"v0.24.0", "ef7b29c06bdf50f4f7db5c8b0b26759fcbe90680", "e27726c60f59ed2a44a551d4fa3e66f82f31577cedcaaa9c97fa8b07b452d1df", "8c39e22c6abe6a15f060b583133de1ed8135b3927eed6ae8411671f11dcf5bd6", "5a23c4050bd4444f1a3565b669c8e23ce820078e8bfbe03e37529230009b1602"},
	{"v0.25.0", "44479b3d7140188a061e7814a465444b59cbd43c", "e27726c60f59ed2a44a551d4fa3e66f82f31577cedcaaa9c97fa8b07b452d1df", "1b34714852ae6847dee824e5a9d61791834045efcfcd2c76c27728f31fd2ef69", "5a23c4050bd4444f1a3565b669c8e23ce820078e8bfbe03e37529230009b1602"},
	{"v0.26.0", "ef33adb71ce1bffb0ab1fce593625c320dc6164e", "337c865ccc0d823d5f0d4e2ac90b4bc14d0e0ac3a2009b14c89f5e79d39f1d73", "1b34714852ae6847dee824e5a9d61791834045efcfcd2c76c27728f31fd2ef69", "8341eb5914375b1c4467539253e48529da3c032cfdc3ff64b44d47ec6168d479"},
	{"v0.27.0", "71954323c9191e6171f3eb04f80bb46a5f128306", "81cec00d4d324da02774ca9c4499a2162b035143241cc3f369a94c543373c6aa", "70bd3c26bc4aed941afce261553cc3b0495b1b4247fbae0ae6564b298469e08e", "8341eb5914375b1c4467539253e48529da3c032cfdc3ff64b44d47ec6168d479"},
}

// literalKustomizationAllowed recognizes one immutable, comment-only action.
// It parses original bytes and does not substitute, evaluate, or normalize.
func literalKustomizationAllowed(ctx literalKustomizationContext, data []byte) bool {
	pin, ok := literalKustomizationPinFor(ctx)
	if !ok || sha256Hex(data) != pin.Kustomization {
		return false
	}
	return literalKustomizationCommentOnly(data)
}

func literalKustomizationCommentOnly(data []byte) bool {
	roots, _, err := decodeStrict(data)
	if err != nil || bytes.Count(data, []byte(templateMarker)) != 1 || bytes.Count(data, []byte(literalKustomizationAction)) != 1 || bytes.Count(data, []byte("}}")) != 1 {
		return false
	}
	comments := 0
	for _, root := range roots {
		comments += literalKustomizationCommentActions(root)
	}
	return comments == 1
}

func literalKustomizationPinFor(ctx literalKustomizationContext) (literalKustomizationPin, bool) {
	if ctx.Project != literalKustomizationProject || ctx.Repo != literalKustomizationRepo || ctx.Path != literalKustomizationPath || len(ctx.Referrers) != 1 || ctx.Referrers[0] != (literalKustomizationReferrer{Path: "config/default/kustomization.yaml", Kind: "kustomize"}) {
		return literalKustomizationPin{}, false
	}
	for _, pin := range literalKustomizationPins {
		if ctx.Tag == pin.Tag && ctx.Commit == pin.Commit && ctx.MakefileSHA256 == pin.Makefile && ctx.DefaultSHA256 == pin.Default {
			return pin, true
		}
	}
	return literalKustomizationPin{}, false
}

func literalKustomizationCommentActions(node *yaml.Node) int {
	if node == nil {
		return 0
	}
	n := strings.Count(node.HeadComment, literalKustomizationAction) + strings.Count(node.LineComment, literalKustomizationAction) + strings.Count(node.FootComment, literalKustomizationAction)
	for _, child := range node.Content {
		n += literalKustomizationCommentActions(child)
	}
	return n
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
