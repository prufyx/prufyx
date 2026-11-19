// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/extract/chartapisurface"
	"github.com/prufyx/prufyx/cli/internal/servedapis"
)

const chartAPISurfaceUsage = "chart-api-surface: usage: prufyx-maintainer chart-api-surface --chart ARCHIVE --out LEDGER.json [--served-apis FILE --lines 1.25,1.26] [--oracle-cmd ABSOLUTE-PATH]"

const maxServedAPIsFileBytes = 64 << 20

var chartLineRE = regexp.MustCompile(`^[0-9]{1,3}\.[0-9]{1,3}$`)

// runChartAPISurface is the measurement-mode reader: it writes a ledger of
// the (apiVersion, kind) pairs a pinned chart archive can produce and, with
// served lists, a would-block / would-pass / withheld measurement per line.
// It writes no rule and no attestation.
func runChartAPISurface(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("chart-api-surface", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	chart := fs.String("chart", "", "pinned chart archive (.tgz)")
	out := fs.String("out", "", "ledger file to write")
	served := fs.String("served-apis", "", "served-API document (servedapis format)")
	linesFlag := fs.String("lines", "", "Kubernetes lines to check, comma separated")
	oracle := fs.String("oracle-cmd", "", "optional absolute path of an offline renderer (see docs)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *chart == "" || *out == "" {
		return &commandError{code: 2, message: chartAPISurfaceUsage}
	}
	if (*served == "") != (*linesFlag == "") {
		return &commandError{code: 2, message: "chart-api-surface: --served-apis and --lines go together"}
	}
	raw, err := readSurfaceInput(*chart, chartapisurface.MaxArchiveBytes)
	if err != nil {
		return &commandError{code: 1, message: "chart-api-surface: " + err.Error()}
	}
	led, err := chartapisurface.Read(raw)
	if err != nil {
		return &commandError{code: 1, message: "chart-api-surface: " + err.Error()}
	}
	if *oracle != "" {
		rendered, err := chartapisurface.RunOracleCommand(*oracle, *chart)
		if err != nil {
			led.MarkOracleUnavailable(err.Error())
		} else {
			led.ApplyOracle(rendered)
		}
	}
	if *served != "" {
		var lines []string
		seen := map[string]bool{}
		for _, l := range strings.Split(*linesFlag, ",") {
			l = strings.TrimSpace(l)
			if !chartLineRE.MatchString(l) || seen[l] {
				return &commandError{code: 2, message: "chart-api-surface: --lines needs unique major.minor values"}
			}
			seen[l] = true
			lines = append(lines, l)
		}
		doc, err := readSurfaceInput(*served, maxServedAPIsFileBytes)
		if err != nil {
			return &commandError{code: 1, message: "chart-api-surface: " + err.Error()}
		}
		records, err := servedapis.Parse(doc)
		if err != nil {
			return &commandError{code: 1, message: "chart-api-surface: " + err.Error()}
		}
		led.CheckServed(records, lines)
	}
	led.Finish()
	b, err := led.Marshal()
	if err != nil {
		return &commandError{code: 1, message: "chart-api-surface: " + err.Error()}
	}
	if err := os.WriteFile(*out, b, 0o644); err != nil {
		return &commandError{code: 1, message: "chart-api-surface: " + err.Error()}
	}
	fmt.Fprintf(stdout, "chart-api-surface: %s %s %s (%d entries, %d withheld codes)\n", led.Chart.Name, led.Chart.Version, led.Status, len(led.APIs), len(led.Withheld))
	return nil
}

func readSurfaceInput(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > max {
		return nil, fmt.Errorf("%s is not a regular file within %d bytes", path, max)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil || int64(len(b)) > max {
		return nil, fmt.Errorf("%s is not readable within %d bytes", path, max)
	}
	return b, nil
}
