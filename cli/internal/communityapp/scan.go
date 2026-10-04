// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"errors"
	"fmt"
	"io"
	"os"

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
	result, err := scanrun.Run(request, scanrun.Options{Stdin: stdin})
	if err != nil {
		return r.scanError(err)
	}
	output, err := scanreport.Render(result.Report, request.Format, scanreport.RenderOptions{ShowPasses: request.ShowPasses, Verbose: request.Verbose})
	if err != nil {
		return r.fail(scanreport.UsageIntegrity, ExitIntegrity)
	}
	if _, err := r.stdout.Write(output); err != nil {
		return ExitIntegrity
	}
	return result.Exit
}

func (r runtime) scanError(err error) int {
	var usageErr *scanrun.UsageError
	if errors.As(err, &usageErr) {
		return r.fail(usageErr.Message, ExitUsage)
	}
	var storeErr *scanrun.StoreError
	if errors.As(err, &storeErr) {
		return r.fail(storeErr.Error(), ExitIntegrity)
	}
	return r.fail(scanreport.UsageIntegrity, ExitIntegrity)
}

// scanStdin is the standard input a scan reads for "-".
var scanStdin io.Reader = os.Stdin
