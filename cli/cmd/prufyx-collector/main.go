// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/prufyx/prufyx/cli/internal/localcollector"
)

type stringsFlag []string

func (s *stringsFlag) String() string     { return fmt.Sprint([]string(*s)) }
func (s *stringsFlag) Set(v string) error { *s = append(*s, v); return nil }

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "collect" {
		printUsage(stderr)
		return 2
	}
	if len(args) == 2 && (args[1] == "-h" || args[1] == "--help") {
		printUsage(stdout)
		return 0
	}
	if len(args) < 2 {
		fmt.Fprintln(stderr, "Output directory is required.")
		return 2
	}
	output := args[1]
	if strings.HasPrefix(output, "-") {
		fmt.Fprintln(stderr, "Output directory must precede collector options.")
		return 2
	}
	if duplicateOption(args[2:], "--kubeconfig") || duplicateOption(args[2:], "--component-configuration-profile") || duplicateOption(args[2:], "--kubectl") {
		fmt.Fprintln(stderr, "A singleton collector option was supplied more than once.")
		return 2
	}
	fs := flag.NewFlagSet("prufyx-collector collect", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var kubeconfig, profile, kubectl string
	var pods, components, partial, ack bool
	var execEnv stringsFlag
	fs.StringVar(&kubeconfig, "kubeconfig", "", "explicit private kubeconfig")
	fs.BoolVar(&pods, "include-pod-status-images", false, "collect filtered Pod status image aggregates")
	fs.BoolVar(&components, "include-component-configuration", false, "collect bounded public component configuration")
	fs.StringVar(&profile, "component-configuration-profile", "v2", "v2 or v3")
	fs.BoolVar(&partial, "allow-partial", false, "accept bounded omissions")
	fs.BoolVar(&ack, "acknowledge-kubeconfig-exec-risk", false, "acknowledge kubeconfig authentication helpers")
	fs.Var(&execEnv, "exec-env", "forward one named ambient variable; repeatable")
	fs.StringVar(&kubectl, "kubectl", "", "kubectl executable (default PATH lookup)")
	if err := fs.Parse(args[2:]); err != nil {
		if err == flag.ErrHelp {
			printUsage(stdout)
			return 0
		}
		fmt.Fprintln(stderr, "Invalid collector options. Run prufyx-collector collect --help for the supported form.")
		return 2
	}
	if optionPresent(args[2:], "--component-configuration-profile") && !components {
		fmt.Fprintln(stderr, "--component-configuration-profile requires --include-component-configuration.")
		return 2
	}
	opts := localcollector.Options{OutputRoot: output, Kubeconfig: kubeconfig, Contexts: fs.Args(), IncludePodStatusImages: pods, IncludeComponentConfiguration: components, ComponentConfigurationProfile: profile, AllowPartial: partial, AcknowledgeExecRisk: ack, ExecEnv: execEnv, Kubectl: kubectl}
	_, code := (localcollector.Collector{}).Collect(ctx, opts, stdout, stderr)
	return code
}

func printUsage(out io.Writer) {
	fmt.Fprintln(out, "Usage: prufyx-collector collect OUTPUT_DIR --kubeconfig FILE [OPTIONS] CONTEXT...")
	fmt.Fprintln(out, "Read-only options: --include-pod-status-images, --include-component-configuration, --component-configuration-profile v2|v3, --allow-partial, --acknowledge-kubeconfig-exec-risk, --exec-env NAME, --kubectl PATH")
}

func optionPresent(args []string, name string) bool {
	for _, arg := range optionTokens(args) {
		if matchesOption(arg, name) {
			return true
		}
	}
	return false
}

func duplicateOption(args []string, name string) bool {
	count := 0
	for _, arg := range optionTokens(args) {
		if matchesOption(arg, name) {
			count++
		}
	}
	return count > 1
}

func optionTokens(args []string) []string {
	var out []string
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" || !strings.HasPrefix(arg, "-") || arg == "-" {
			break
		}
		out = append(out, arg)
		name := strings.TrimLeft(strings.SplitN(arg, "=", 2)[0], "-")
		if !strings.Contains(arg, "=") && (name == "kubeconfig" || name == "component-configuration-profile" || name == "exec-env" || name == "kubectl") {
			i++ // flag.Parse treats the next token as this option's value
		}
	}
	return out
}

func matchesOption(arg, name string) bool {
	canonical := strings.TrimPrefix(name, "--")
	token := strings.TrimLeft(strings.SplitN(arg, "=", 2)[0], "-")
	return token == canonical
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}
