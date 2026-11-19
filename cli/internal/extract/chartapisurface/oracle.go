// SPDX-License-Identifier: AGPL-3.0-only

package chartapisurface

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"
)

// Oracle bounds.
const (
	MaxOracleBytes   = 16 << 20
	MaxOracleDocs    = 4096
	OracleTimeout    = 60 * time.Second
	OracleWaitDelay  = 5 * time.Second
	OracleOK         = "ok"
	OracleMismatch   = "mismatch"
	OracleExtraOnWH  = "extra_objects_chart_withheld"
	OracleUnreadable = "unreadable"
)

// RenderedPairs reads the (apiVersion, kind) of every document of an offline
// render with default values. Anything that is not a mapping with string
// apiVersion and kind is refused.
func RenderedPairs(rendered []byte) ([]Pair, error) {
	if len(rendered) > MaxOracleBytes {
		return nil, fmt.Errorf("render beyond %d bytes", MaxOracleBytes)
	}
	dec := yaml.NewDecoder(bytes.NewReader(rendered))
	var out []Pair
	for n := 0; ; n++ {
		if n > MaxOracleDocs {
			return nil, fmt.Errorf("render beyond %d documents", MaxOracleDocs)
		}
		var doc map[string]any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("render is not YAML: %v", err)
		}
		if len(doc) == 0 {
			continue
		}
		av, ok1 := doc["apiVersion"].(string)
		k, ok2 := doc["kind"].(string)
		if !ok1 || !ok2 {
			return nil, errors.New("a rendered document has no string apiVersion and kind")
		}
		out = append(out, Pair{av, k})
	}
	sortPairs(out)
	return out, nil
}

// ApplyOracle compares an offline render with the static set. Every
// rendered pair must be in the static set. A miss on a complete chart is a
// tool bug and withholds the chart; on a chart already withheld it only says
// the withheld codes explain the difference.
func (l *Ledger) ApplyOracle(rendered []byte) {
	pairs, err := RenderedPairs(rendered)
	if err != nil {
		l.Oracle = &OracleResult{Result: OracleUnreadable, Missing: []Pair{}}
		l.Withheld = append(l.Withheld, Withheld{Code: CodeOracleUnavailable, Detail: err.Error()})
		l.Finish()
		return
	}
	static := map[Pair]bool{}
	for _, p := range l.Pairs() {
		static[p] = true
	}
	missing := []Pair{}
	seen := map[Pair]bool{}
	for _, p := range pairs {
		if !static[p] && !seen[p] {
			missing = append(missing, p)
		}
		seen[p] = true
	}
	res := &OracleResult{Result: OracleOK, Missing: missing}
	if len(missing) > 0 {
		if l.Status == StatusComplete {
			res.Result = OracleMismatch
			l.Withheld = append(l.Withheld, Withheld{Code: CodeToolBugOracleMatch, Detail: fmt.Sprintf("%d rendered pairs not in the static set", len(missing))})
		} else {
			res.Result = OracleExtraOnWH
		}
	}
	l.Oracle = res
	l.Finish()
}

// RunOracleCommand runs an operator-provided offline renderer: an absolute
// path, run without a shell, with a private copy of the already-read chart
// archive bytes as its only argument and a bounded time. Its stdout is a
// multi-document YAML render of the chart with default values. The archive is
// not re-opened from its original path, so the render is of the bytes the
// reader scanned. The reader has no renderer of its own and adds no
// dependency; the factory supplies this command.
func RunOracleCommand(cmdPath string, archive []byte) ([]byte, error) {
	if !filepath.IsAbs(cmdPath) {
		return nil, errors.New("oracle command must be an absolute path")
	}
	dir, err := os.MkdirTemp("", "chart-oracle-")
	if err != nil {
		return nil, fmt.Errorf("oracle workspace: %v", err)
	}
	defer os.RemoveAll(dir)
	chartPath := filepath.Join(dir, "chart.tgz")
	if err := os.WriteFile(chartPath, archive, 0o600); err != nil {
		return nil, fmt.Errorf("oracle workspace: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), OracleTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, cmdPath, chartPath)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.WaitDelay = OracleWaitDelay
	var out limitBuf
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("oracle command failed: %v", err)
	}
	if out.over {
		return nil, fmt.Errorf("oracle output beyond %d bytes", MaxOracleBytes)
	}
	return out.b.Bytes(), nil
}

type limitBuf struct {
	b    bytes.Buffer
	over bool
}

func (l *limitBuf) Write(p []byte) (int, error) {
	if l.b.Len()+len(p) > MaxOracleBytes {
		l.over = true
		return 0, errors.New("oracle output too large")
	}
	return l.b.Write(p)
}

// MarkOracleUnavailable withholds the ledger when a requested oracle could
// not run: a check that was asked for and did not happen is not a pass.
func (l *Ledger) MarkOracleUnavailable(reason string) {
	l.Oracle = &OracleResult{Result: OracleUnreadable, Missing: []Pair{}}
	l.Withheld = append(l.Withheld, Withheld{Code: CodeOracleUnavailable, Detail: reason})
	l.Finish()
}
