// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
	"github.com/prufyx/prufyx/cli/internal/scanrun"
)

// scan runs prufyx scan. Parsing, evaluation and rendering live in scanrun
// and scanreport; this only maps the outcome to output and an exit code.
func (r runtime) scan(args []string, stdin io.Reader) int {
	request, err := scanrun.ParseArgs(args)
	if err != nil {
		return r.scanError(err)
	}
	if request.Help {
		fmt.Fprintln(r.stdout, scanreport.Usage)
		return ExitOK
	}
	result, err := scanrun.Run(request, scanrun.Options{Stdin: stdin, AutoLocalDB: true, PinnedRoot: pinnedRootDigest, CompareEmbedded: scanCompareEmbedded, OpenStore: scanOpenStore, ExpiredRoot: scanExpiredRoot})
	if err != nil {
		return r.scanError(err)
	}
	output, err := scanreport.Render(result.Report, request.Format, scanreport.RenderOptions{ShowPasses: request.ShowPasses, Verbose: request.Verbose, OnlyBlocked: request.OnlyBlocked})
	if err != nil {
		return r.fail(scanreport.UsageIntegrity, ExitIntegrity)
	}
	if _, err := r.stdout.Write(output); err != nil {
		return ExitIntegrity
	}
	if result.KnowledgeSource != "" {
		fmt.Fprintln(r.stderr, "prufyx: "+result.KnowledgeSource)
	}
	if result.KnowledgeNote != "" {
		fmt.Fprintln(r.stderr, "prufyx: note: "+result.KnowledgeNote)
	}
	r.knowledgeAgeNote(result.KnowledgeAge)
	if result.PinnedNowWarning != "" {
		fmt.Fprintln(r.stderr, "prufyx: "+result.PinnedNowWarning)
	}
	if note := request.ExitNote(result.Report, result.Exit); note != "" {
		fmt.Fprintln(r.stderr, note)
	}
	return request.ExitCode(result.Report, result.Exit)
}

// scanCompareEmbedded replaces the store/embedded comparison of an automatic
// scan. Test seam; nil is the real comparison.
var scanCompareEmbedded func(map[string]cncfcheck.ExternalBundle) (cncfcheck.EmbeddedComparison, error)

// scanOpenStore and scanExpiredRoot replace opening the default store and
// reading the root of an expired one. Test seams; nil is the real behaviour.
var (
	scanOpenStore   func(path string, projects []string) (*scanrun.Store, error)
	scanExpiredRoot func(storeRoot string) (string, error)
)

func (r runtime) scanError(err error) int {
	var usageErr *scanrun.UsageError
	if errors.As(err, &usageErr) {
		return r.fail(usageErr.Message, ExitUsage)
	}
	var storeErr *scanrun.StoreError
	if errors.As(err, &storeErr) {
		if storeErr.TooNew() {
			return r.fail(storeErr.Error(), ExitKnowledgeTooNew)
		}
		return r.fail(storeErr.Error(), ExitIntegrity)
	}
	return r.fail(scanreport.UsageIntegrity, ExitIntegrity)
}

// scanStdin is the standard input a scan reads for "-".
var scanStdin io.Reader = os.Stdin
