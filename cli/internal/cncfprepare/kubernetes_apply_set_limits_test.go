// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

// A file that mentions template syntax and also exceeds the document bound is
// an error, not an "unparseable" omission that would read as an unresolved set.
func TestKubernetesApplySetDocumentsRejectsOverflowEvenWithTemplateSyntax(t *testing.T) {
	raw := []byte("a: '{{x}}'\n" + strings.Repeat("---\nb: 1\n", 261))
	if _, _, reason, err := kubernetesApplySetDocuments(raw); err == nil {
		t.Fatalf("overflow accepted, reason %q", reason)
	}
}
