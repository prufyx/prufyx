// SPDX-License-Identifier: AGPL-3.0-only

package scanrun

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/intake"
	"github.com/prufyx/prufyx/cli/internal/scanreport"
)

// Request is a parsed scan command line.
type Request struct {
	Paths  []string
	Config string
	// From and To are COMPONENT=VERSION flags; nil when none was given.
	From, To              map[string]string
	Distribution          *string
	ResourceScopeComplete *bool
	TargetApplyRequired   *bool
	Format                string
	ShowPasses, Verbose   bool
	Redact                bool
	Permissions           intake.PermissionPolicy
	PermissionsName       string
	// TrustPolicy is the --require-basis policy; the zero value is the
	// default policy.
	TrustPolicy cncfcheck.TrustPolicy
	// Now is the evaluation instant; zero means the current time.
	Now time.Time
	// KnowledgeDB is the --knowledge-db directory; empty means the embedded
	// knowledge.
	KnowledgeDB string
	Help        bool
}

// UsageError is a command line or input the scan does not accept. Its text
// comes from the message catalog.
type UsageError struct{ Message string }

func (e *UsageError) Error() string { return e.Message }

// ErrIntegrity reports knowledge or report integrity failure.
var ErrIntegrity = errors.New(scanreport.UsageIntegrity)

func usage(format string, args ...any) error {
	return &UsageError{Message: scanreport.Text(format, args...)}
}

// maxArgs bounds the command line.
const maxArgs = 4096

// ParseArgs reads the scan command line. Flags and paths may be mixed;
// "--" ends the flags and "-" is standard input. A flag takes its value as
// the next argument or after "=". Boolean flags accept "=true" and "=false".
func ParseArgs(args []string) (Request, error) {
	request := Request{Format: "human", Permissions: intake.RefuseWritable, PermissionsName: "refuse-writable"}
	if len(args) > maxArgs {
		return Request{}, usage(scanreport.UsageBadValue, "arguments")
	}
	seen := map[string]bool{}
	once := func(name string) error {
		if seen[name] {
			return usage(scanreport.UsageRepeated, name)
		}
		seen[name] = true
		return nil
	}
	flagsDone := false
	for index := 0; index < len(args); index++ {
		arg := args[index]
		if flagsDone || arg == "-" || !strings.HasPrefix(arg, "-") {
			if strings.IndexByte(arg, 0) >= 0 || arg == "" {
				return Request{}, usage(scanreport.UsageBadValue, "PATH")
			}
			request.Paths = append(request.Paths, arg)
			continue
		}
		if arg == "--" {
			flagsDone = true
			continue
		}
		name, value, hasValue := strings.Cut(strings.TrimPrefix(strings.TrimPrefix(arg, "-"), "-"), "=")
		display := "--" + name
		if len(display) > 64 {
			display = display[:64]
		}
		next := func() (string, error) {
			if hasValue {
				return value, nil
			}
			if index+1 >= len(args) {
				return "", usage(scanreport.UsageFlagValue, display)
			}
			index++
			return args[index], nil
		}
		boolean := func() (bool, error) {
			if !hasValue {
				return true, nil
			}
			switch value {
			case "true":
				return true, nil
			case "false":
				return false, nil
			}
			return false, usage(scanreport.UsageBadValue, display)
		}
		switch name {
		case "h", "help":
			request.Help = true
		case "config":
			if err := once(display); err != nil {
				return Request{}, err
			}
			v, err := next()
			if err != nil {
				return Request{}, err
			}
			if v == "" || strings.IndexByte(v, 0) >= 0 {
				return Request{}, usage(scanreport.UsageBadValue, display)
			}
			request.Config = v
		case "from", "to":
			v, err := next()
			if err != nil {
				return Request{}, err
			}
			target := &request.From
			if name == "to" {
				target = &request.To
			}
			if err := addVersion(target, display, v); err != nil {
				return Request{}, err
			}
		case "distribution":
			if err := once(display); err != nil {
				return Request{}, err
			}
			v, err := next()
			if err != nil {
				return Request{}, err
			}
			if v != "official_upstream" && v != "custom_build" {
				return Request{}, usage(scanreport.UsageBadValue, display)
			}
			request.Distribution = &v
		case "resource-scope-complete", "target-api-apply-required":
			if err := once(display); err != nil {
				return Request{}, err
			}
			v, err := boolean()
			if err != nil {
				return Request{}, err
			}
			if name == "resource-scope-complete" {
				request.ResourceScopeComplete = &v
			} else {
				request.TargetApplyRequired = &v
			}
		case "format":
			if err := once(display); err != nil {
				return Request{}, err
			}
			v, err := next()
			if err != nil {
				return Request{}, err
			}
			if !slices.Contains(scanreport.Formats(), v) {
				return Request{}, usage(scanreport.UsageBadValue, display)
			}
			request.Format = v
		case "show-passes", "verbose", "redact":
			if err := once(display); err != nil {
				return Request{}, err
			}
			v, err := boolean()
			if err != nil {
				return Request{}, err
			}
			switch name {
			case "show-passes":
				request.ShowPasses = v
			case "verbose":
				request.Verbose = v
			default:
				request.Redact = v
			}
		case "input-permissions":
			if err := once(display); err != nil {
				return Request{}, err
			}
			v, err := next()
			if err != nil {
				return Request{}, err
			}
			switch v {
			case "strict":
				request.Permissions = intake.Strict
			case "refuse-writable":
				request.Permissions = intake.RefuseWritable
			default:
				return Request{}, usage(scanreport.UsageBadValue, display)
			}
			request.PermissionsName = v
		case "now":
			if err := once(display); err != nil {
				return Request{}, err
			}
			v, err := next()
			if err != nil {
				return Request{}, err
			}
			now, parseErr := time.Parse(time.RFC3339, v)
			if parseErr != nil || now.Location() != time.UTC || now.Format(time.RFC3339) != v || !strings.HasSuffix(v, "Z") {
				return Request{}, usage(scanreport.UsageNow)
			}
			request.Now = now
		case "require-basis":
			if err := once(display); err != nil {
				return Request{}, err
			}
			v, err := next()
			if err != nil {
				return Request{}, err
			}
			policy, parseErr := cncfcheck.ParseTrustPolicy(v)
			if parseErr != nil {
				return Request{}, usage(scanreport.UsageRequireBasis)
			}
			request.TrustPolicy = policy
		case "knowledge-db":
			if err := once(display); err != nil {
				return Request{}, err
			}
			v, err := next()
			if err != nil {
				return Request{}, err
			}
			if v == "" || len(v) > 4096 || !printable(v) {
				return Request{}, usage(scanreport.UsageBadValue, display)
			}
			request.KnowledgeDB = v
		default:
			return Request{}, usage(scanreport.UsageUnknownFlag, display)
		}
	}
	stdin := 0
	for _, path := range request.Paths {
		if path == "-" {
			stdin++
		}
	}
	if stdin > 1 {
		return Request{}, usage(scanreport.UsageStdinTwice)
	}
	if request.KnowledgeDB != "" && !request.Now.IsZero() {
		return Request{}, usage(scanreport.UsageKnowledgeDBNow)
	}
	return request, nil
}

// printable reports text without control characters, so it can be shown
// in the report as given.
func printable(text string) bool {
	for _, r := range text {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// addVersion records COMPONENT=VERSION. The component name is checked
// against the catalog later; the version must be X.Y.Z here. The same
// component twice is accepted only with the same version.
func addVersion(target *map[string]string, flagName, value string) error {
	component, version, ok := strings.Cut(value, "=")
	if !ok || component == "" || version == "" || len(component) > 128 || len(version) > 64 {
		return usage(scanreport.UsageComponentVersion, flagName)
	}
	if !validVersion(version) {
		return usage(scanreport.UsageVersion, quote(version), quote(component))
	}
	if *target == nil {
		*target = map[string]string{}
	}
	if existing, found := (*target)[component]; found && existing != version {
		return usage(scanreport.UsageConflict, flagName, quote(component))
	}
	(*target)[component] = version
	return nil
}

// validVersion is X.Y.Z with decimal parts, no leading zeros and at most
// nine digits each: the version grammar of the configuration file.
func validVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" || len(part) > 9 || (len(part) > 1 && part[0] == '0') {
			return false
		}
		for _, c := range part {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

// quote shows user text in a message, bounded and with control characters
// escaped.
func quote(text string) string {
	if len(text) > 48 {
		text = text[:48]
	}
	var out strings.Builder
	out.WriteByte('"')
	for _, r := range text {
		if r < 0x20 || r == 0x7f || r == '"' || r == '\\' {
			out.WriteString("?")
			continue
		}
		out.WriteRune(r)
	}
	out.WriteByte('"')
	return out.String()
}
