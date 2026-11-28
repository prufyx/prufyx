// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"os"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/extract/extractpack"
)

const (
	servedOptInSchema = `"prufyx.io/cncf-source-rule-pack/v1alpha16"`
	servedBaseSchema  = `"prufyx.io/cncf-source-rule-pack/v1alpha4"`
)

func runServedAdmit(t *testing.T, pack string, admit func(string, []byte) error) error {
	t.Helper()
	src := newServedFakeSource(t)
	var out bytes.Buffer
	return runServedListsWith([]string{"build", "--pack", pack, "--lines", "1.30", "--now", servedTestNow}, &out, servedListsDeps{
		source: func(string) (servedSource, error) { return src, nil },
		admit:  admit,
	})
}

// A served-list build never declares an opt-in level, even when the loader
// would admit the pack only there.
func TestServedListsBuildNeverDeclaresAnOptInLevel(t *testing.T) {
	pack := servedPackDir(t)
	before, err := os.ReadFile(pack)
	if err != nil {
		t.Fatal(err)
	}
	calls, optIn := 0, 0
	err = runServedAdmit(t, pack, func(_ string, raw []byte) error {
		calls++
		if bytes.Contains(raw, []byte(servedOptInSchema)) {
			optIn++
			return nil
		}
		return errors.New("refused")
	})
	// Levels 4 to 4+servedSchemaLevels include 16, which is skipped.
	if err == nil || optIn != 0 || calls != servedSchemaLevels {
		t.Fatalf("err=%v calls=%d opt-in tries=%d", err, calls, optIn)
	}
	after, err := os.ReadFile(pack)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("the pack changed (%v)", err)
	}
}

// A pack that already declares the level keeps it.
func TestServedListsBuildKeepsADeclaredOptInLevel(t *testing.T) {
	pack := servedPackDir(t)
	raw, err := os.ReadFile(pack)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := extractpack.ParsePack(raw)
	if err != nil {
		t.Fatal(err)
	}
	if string(parsed.Members["schema"]) != servedBaseSchema {
		t.Fatalf("fixture schema %s", parsed.Members["schema"])
	}
	parsed.Members["schema"] = []byte(servedOptInSchema)
	if raw, err = parsed.Render(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pack, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runServedAdmit(t, pack, func(_ string, raw []byte) error {
		if !bytes.Contains(raw, []byte(servedOptInSchema)) {
			return errors.New("refused")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(pack)
	if err != nil || !bytes.Contains(after, []byte(servedOptInSchema)) {
		t.Fatalf("the declared level was lost (%v)", err)
	}
}
