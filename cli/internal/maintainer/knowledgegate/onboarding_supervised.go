// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"
)

// These hashes establish byte correspondence with the trusted supervisor's
// capture. A caller-supplied hash is not source, policy or signing authority.
type supervisedFlags struct {
	executable, draft, keys, export, daily string
}

func (s *supervisedFlags) register(f *flag.FlagSet) {
	f.StringVar(&s.executable, "admission-executable-sha256", "", "raw SHA256 of the authenticated BASE executable")
	f.StringVar(&s.draft, "admission-draft-sha256", "", "raw SHA256 of the supervisor's frozen draft")
	f.StringVar(&s.keys, "admission-keys-sha256", "", "raw SHA256 of the frozen BASE public key file (including its newline)")
	f.StringVar(&s.export, "admission-export-sha256", "", "raw SHA256 of the frozen typed export binding")
	f.StringVar(&s.daily, "admission-daily-sha256", "", "raw SHA256 of the frozen daily observations")
}

type supervisedInputs struct {
	files [6]*os.File // fixed fd3 readiness, fd4 executable, fd5..8 inputs
}

func (s *supervisedInputs) close() {
	if s == nil {
		return
	}
	for i, f := range s.files {
		if f != nil {
			_ = f.Close()
			s.files[i] = nil
		}
	}
}

// SupervisedApprovalMain runs before the outer command's generic validation.
// Even malformed/partial supervised requests first claim and close their fixed
// descriptors. Unrelated commands retain their existing dispatch and behavior.
func SupervisedApprovalMain(args []string, stdin io.Reader, stdout, stderr io.Writer) (bool, int) {
	if len(args) < 2 || args[0] != "approval" || args[1] != "sign-supervised" {
		return false, 0
	}
	env := approvalEnv{stdin: stdin, now: time.Now, checkStdin: checkKeyStdin, confirm: confirmOnTTY, random: rand.Reader}
	return true, supervisedApprovalMain(args[1:], env, DefaultLayout(), stdout, stderr)
}

func supervisedApprovalMain(args []string, env approvalEnv, layout Layout, stdout, stderr io.Writer) int {
	inputs, err := claimSupervisedInputs()
	if inputs != nil {
		defer inputs.close()
	}
	if err != nil {
		fmt.Fprintf(stderr, "approval: supervised inputs: %s\n", logSafe(err.Error()))
		return 2
	}
	if len(args) == 0 || args[0] != "sign-supervised" {
		fmt.Fprintln(stderr, "approval: supervised mode is onboarding-bot signing only")
		return 2
	}
	env.supervised = inputs
	return approvalMain(args, env, layout, stdout, stderr)
}

func (s supervisedFlags) valid() error {
	for _, v := range []string{s.executable, s.draft, s.keys, s.export, s.daily} {
		if len(v) != 64 || !validBatchDigest("sha256:"+v) {
			return errors.New("complete raw supervised SHA256 bindings required")
		}
	}
	return nil
}
