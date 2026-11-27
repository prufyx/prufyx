// SPDX-License-Identifier: AGPL-3.0-only
package extractcli

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/prufyx/prufyx/cli/internal/extract/decision"
	"github.com/prufyx/prufyx/cli/internal/extract/safefs"
)

const decisionCheckSchema = "prufyx.io/extract-decision-check/v1"

type decisionHashes struct {
	Decision string `json:"decisionSHA256"`
	Receipt  string `json:"receiptSHA256"`
}
type decisionCheck struct {
	Schema string          `json:"schema"`
	Result string          `json:"result"`
	Left   *decisionHashes `json:"left,omitempty"`
	Right  *decisionHashes `json:"right,omitempty"`
}

func hashes(p decision.Pair) *decisionHashes {
	sum := func(b []byte) string { v := sha256.Sum256(b); return "sha256:" + hex.EncodeToString(v[:]) }
	return &decisionHashes{Decision: sum(p.Decision), Receipt: sum(p.Receipt)}
}
func cmdDecisions(args []string, stdout io.Writer) (code int, err error) {
	result := decisionCheck{Schema: decisionCheckSchema, Result: "INVALID"}
	defer func() {
		if err != nil {
			code = 2
			result.Result = "INVALID"
			result.Left = nil
			result.Right = nil
		}
		if e := json.NewEncoder(stdout).Encode(result); e != nil {
			code = 2
			err = fmt.Errorf("write decision result: %w", e)
		}
	}()

	f := flag.NewFlagSet("extract decisions", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	from := f.String("from", "", "legacy run directory")
	out := f.String("out", "", "new decision/receipt directory")
	verify := f.String("verify", "", "validate a decision/receipt directory")
	compare := f.String("compare", "", "left decision/receipt directory")
	with := f.String("with", "", "right decision/receipt directory")
	if e := f.Parse(args); e != nil || f.NArg() != 0 {
		return 2, errors.New("invalid decisions command")
	}
	switch {
	case *from != "" && *out != "" && *verify == "" && *compare == "" && *with == "":
		files, e := decision.ReadDirectory(*from)
		if e != nil {
			return 2, e
		}
		p, e := decision.Bridge(files)
		if e != nil {
			return 2, e
		}
		rendered, e := p.Files()
		if e != nil {
			return 2, e
		}
		if e = safefs.WriteTree(*out, rendered); e != nil {
			return 2, e
		}
		result.Result = "VALID"
		result.Left = hashes(p)
		return 0, nil
	case *verify != "" && *from == "" && *out == "" && *compare == "" && *with == "":
		p, e := decision.ReadPair(*verify)
		if e != nil {
			return 2, e
		}
		result.Result = "VALID"
		result.Left = hashes(p)
		return 0, nil
	case *compare != "" && *with != "" && *from == "" && *out == "" && *verify == "":
		a, e := decision.ReadPair(*compare)
		if e != nil {
			return 2, e
		}
		b, e := decision.ReadPair(*with)
		if e != nil {
			return 2, e
		}
		same, e := decision.Equal(a, b)
		if e != nil {
			return 2, e
		}
		result.Left = hashes(a)
		result.Right = hashes(b)
		if !same {
			result.Result = "DIFFERENT"
			return 1, nil
		}
		result.Result = "EQUAL"
		return 0, nil
	default:
		return 2, errors.New("give --from DIR --out DIR, --verify DIR, or --compare DIR --with DIR")
	}
}
