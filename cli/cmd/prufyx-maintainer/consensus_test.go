// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestConsensusDispatch(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"consensus", "help"}, &out, &errOut); err != nil || !strings.Contains(out.String(), "prufyx-maintainer consensus verify --claims FILE") {
		t.Fatalf("help: %v %q", err, out.String())
	}
	err := run([]string{"consensus", "verify"}, &out, &errOut)
	var command *commandError
	if !errors.As(err, &command) || command.code != 2 || !command.printed {
		t.Fatalf("misuse: %v", err)
	}
	out.Reset()
	if err := run([]string{"help"}, &out, &errOut); err != nil || !strings.Contains(out.String(), "|consensus|") {
		t.Fatalf("top-level help: %v %q", err, out.String())
	}
}
