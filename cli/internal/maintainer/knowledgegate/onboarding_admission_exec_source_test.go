// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// seamSources parses every non-test Go file of the package.
func seamSources(t *testing.T) map[string]*ast.File {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := map[string]*ast.File{}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		out[name] = f
	}
	return out
}

// setter is one place a struct member is written: an assignment through a
// selector, or a key of a composite literal.
type setter struct{ file, fn, recv string }

// setters lists every non-test write of the member named field.
func setters(t *testing.T, field string) []setter {
	t.Helper()
	var out []setter
	for name, f := range seamSources(t) {
		for _, d := range f.Decls {
			fd, ok := d.(*ast.FuncDecl)
			if !ok {
				// Package-level literals are scanned too.
				ast.Inspect(d, func(n ast.Node) bool {
					if kv, ok := n.(*ast.KeyValueExpr); ok {
						if id, ok := kv.Key.(*ast.Ident); ok && id.Name == field {
							out = append(out, setter{name, "<package>", ""})
						}
					}
					return true
				})
				continue
			}
			ast.Inspect(fd, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.AssignStmt:
					for _, l := range x.Lhs {
						if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == field {
							recv := ""
							if id, ok := sel.X.(*ast.Ident); ok {
								recv = id.Name
							}
							out = append(out, setter{name, fd.Name.Name, recv})
						}
					}
				case *ast.KeyValueExpr:
					if id, ok := x.Key.(*ast.Ident); ok && id.Name == field {
						out = append(out, setter{name, fd.Name.Name, ""})
					}
				case *ast.UnaryExpr:
					// &x.Field passes a pointer to the member to a writer.
					if sel, ok := x.X.(*ast.SelectorExpr); ok && x.Op == token.AND && sel.Sel.Name == field {
						out = append(out, setter{name, fd.Name.Name, "&"})
					}
				}
				return true
			})
		}
	}
	return out
}

// The verify-pr member of the admission input is written only by the
// in-process seam. The decision's own member (written by the pure checker from
// its input) is the one other write, by name.
func TestVerifyPrHasNoRuntimeSetterOutsideTheSeam(t *testing.T) {
	t.Parallel()
	for _, s := range setters(t, "VerifyPr") {
		switch {
		case s.file == "onboarding_admission_exec.go":
		case s.file == "onboarding_admission.go" && s.fn == "AdmitOnboardingAuto" && s.recv == "d":
		default:
			t.Errorf("VerifyPr is written outside the seam: %+v", s)
		}
	}
	// The seam does write it (the test is not vacuous).
	found := false
	for _, s := range setters(t, "VerifyPr") {
		found = found || s.file == "onboarding_admission_exec.go"
	}
	if !found {
		t.Fatal("the seam no longer writes the result")
	}
}

// The refusal list is written by the seam only, and the run-time lock and the
// test hooks have exactly the setters they are meant to have.
func TestSeamMembersHaveNoOtherSetter(t *testing.T) {
	t.Parallel()
	for field, allowed := range map[string][]string{
		"SeamRefusals":                 {"onboarding_admission_exec.go"},
		"OnboardingAdmissionInProcess": {"cli.go"},
		"AdmissionEvent":               {"cli.go"},
		"AdmissionRunner":              nil,
		"AdmissionVerifier":            nil,
	} {
		for _, s := range setters(t, field) {
			ok := false
			for _, a := range allowed {
				ok = ok || s.file == a
			}
			if !ok {
				t.Errorf("%s is written in %+v", field, s)
			}
		}
	}
	// The lock has its one setter, at the command line.
	if got := setters(t, "OnboardingAdmissionInProcess"); len(got) != 1 || got[0].fn != "cmdVerify" {
		t.Fatalf("lock setters %+v", got)
	}
}

// The files of the seam read no environment variable, home, working
// directory, argument list or file by name, and start no child without an
// explicit environment: nothing outside the authenticated objects can steer
// them. The few filesystem uses are listed with the reason.
func TestSeamFilesReadNoEnvironment(t *testing.T) {
	t.Parallel()
	forbidden := map[string]bool{"Getenv": true, "LookupEnv": true, "Environ": true, "ReadFile": true, "Open": true, "OpenFile": true,
		"Setenv": true, "ExpandEnv": true, "UserHomeDir": true, "UserCacheDir": true, "UserConfigDir": true, "Args": true, "Getwd": true,
		"MkdirTemp": true, "CreateTemp": true, "TempDir": true, "Stat": true, "Lstat": true, "ReadDir": true, "Executable": true, "Hostname": true}
	// file -> os function -> why it is fine.
	allowed := map[string]map[string]string{
		"onboarding_admission_runner.go": {
			"MkdirTemp": "empty scratch HOME of the child (TMPDIR only picks where the empty directory lives; the child's environment is set explicitly in runnerExec)",
			"Stat":      "existence of the fixed absolute git paths, nothing read",
		},
		"onboarding_binding.go":        {"MkdirTemp": "scratch directory for the exported authenticated trees; gitCommand sets the child environment explicitly"},
		"onboarding_admission_exec.go": {"Lstat": "reads only the gate's own exported scratch tree (symbolic link check)"},
	}
	srcs := seamSources(t)
	for _, name := range []string{"onboarding_admission_exec.go", "onboarding_admission_runner.go", "onboarding_binding.go", "onboarding_admission_runner_unix.go", "onboarding_admission_runner_other.go"} {
		f := srcs[name]
		if f == nil {
			t.Fatalf("%s missing", name)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, "\"")
			if path == "os/user" {
				t.Errorf("%s imports os/user", name)
			}
			if path == "os" && imp.Name != nil {
				t.Errorf("%s imports os under another name or dot", name)
			}
		}
		hasCmd, setsEnv := false, false
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := x.X.(*ast.Ident); ok && id.Name == "os" && forbidden[x.Sel.Name] {
					if _, ok := allowed[name][x.Sel.Name]; !ok {
						t.Errorf("%s uses os.%s", name, x.Sel.Name)
					}
				}
				if id, ok := x.X.(*ast.Ident); ok && id.Name == "exec" && strings.HasPrefix(x.Sel.Name, "Command") {
					hasCmd = true
				}
			case *ast.AssignStmt:
				for _, l := range x.Lhs {
					if sel, ok := l.(*ast.SelectorExpr); ok && sel.Sel.Name == "Env" {
						setsEnv = true
					}
				}
			}
			return true
		})
		if hasCmd && !setsEnv {
			t.Errorf("%s starts a command without setting its environment", name)
		}
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		// No verify-pr artifact or result file is named anywhere.
		if strings.Contains(string(raw), "verify-pr-result.json") || strings.Contains(string(raw), "verify-pr-result\"") || strings.Contains(string(raw), "VERIFY_PR") {
			t.Errorf("%s names a verify-pr result file or variable", name)
		}
	}
	// onboarding_binding.go starts its commands through gitCommand, which sets
	// the environment; the exec file and the runner start none or set it.
}

// The package may import the verifier only because the verifier never imports
// the gate back (no cycle, and no hidden call path the other way).
func TestTargetdraftDoesNotImportTheGate(t *testing.T) {
	t.Parallel()
	files, err := filepath.Glob(filepath.Join("..", "targetdraft", "*.go"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no targetdraft sources: %v", err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			if strings.Contains(imp.Path.Value, "maintainer/knowledgegate") {
				t.Errorf("%s imports the gate: %s", name, imp.Path.Value)
			}
		}
	}
}
