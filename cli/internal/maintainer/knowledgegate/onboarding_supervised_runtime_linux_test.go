// SPDX-License-Identifier: AGPL-3.0-only

//go:build linux

package knowledgegate

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSupervisedPartialDescriptorsKeepRuntime(t *testing.T) {
	program := filepath.Join(t.TempDir(), "early-runtime")
	claim, err := os.ReadFile("onboarding_supervised_unix.go")
	if err != nil {
		t.Fatal(err)
	}
	common, err := os.ReadFile("onboarding_supervised.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	tree, err := parser.ParseFile(fset, "onboarding_supervised.go", common, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	var scopeType, scopeClose []byte
	for _, decl := range tree.Decls {
		if group, ok := decl.(*ast.GenDecl); ok && group.Tok == token.TYPE {
			for _, spec := range group.Specs {
				if typ, ok := spec.(*ast.TypeSpec); ok && typ.Name.Name == "supervisedInputs" {
					scopeType = append([]byte("type "), common[fset.Position(typ.Pos()).Offset:fset.Position(typ.End()).Offset]...)
				}
			}
		}
		if fn, ok := decl.(*ast.FuncDecl); ok && fn.Name.Name == "close" && fn.Recv != nil && len(fn.Recv.List) == 1 {
			if ptr, ok := fn.Recv.List[0].Type.(*ast.StarExpr); ok {
				if name, ok := ptr.X.(*ast.Ident); ok && name.Name == "supervisedInputs" {
					scopeClose = common[fset.Position(fn.Pos()).Offset:fset.Position(fn.End()).Offset]
				}
			}
		}
	}
	if len(scopeType) == 0 || len(scopeClose) == 0 {
		t.Fatal("production scope type/cleanup unavailable")
	}
	wrapper, err := os.ReadFile("./testdata/supervised-runtime/runtime_test.go")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	claimPath := filepath.Join(dir, "claim_unix.go")
	boundPath := filepath.Join(dir, "bound_test.go")
	wrapperPath := filepath.Join(dir, "runtime_test.go")
	bound := append([]byte("package knowledgegate\nimport \"os\"\n"), scopeType...)
	bound = append(bound, '\n')
	bound = append(bound, scopeClose...)
	for name, raw := range map[string][]byte{claimPath: claim, boundPath: bound, wrapperPath: wrapper} {
		if err := os.WriteFile(name, raw, 0600); err != nil {
			t.Fatal(err)
		}
		read, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(read, raw) {
			t.Fatal("bound test build source differs")
		}
	}
	build := exec.Command("go", "test", "-c", "-o", program, claimPath, boundPath, wrapperPath)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build unchanged production claim fixture: %v %s", err, out)
	}
	for name, want := range map[string][]byte{"onboarding_supervised_unix.go": claim, "onboarding_supervised.go": common} {
		raw, err := os.ReadFile(name)
		if err != nil || !bytes.Equal(raw, want) {
			t.Fatal("production source changed during bound build")
		}
	}
	t.Logf("bound production claim SHA256 %x; scope/close source SHA256 %x", sha256.Sum256(claim), sha256.Sum256(common))
	for _, warm := range []bool{false, true} {
		for _, missing := range []bool{false, true} {
			t.Run(fmt.Sprintf("missing-middle-%t-warm-%t", missing, warm), func(t *testing.T) {
				read, write, err := os.Pipe()
				if err != nil {
					t.Fatal(err)
				}
				defer read.Close()
				defer write.Close()
				fd, err := unix.Dup(int(write.Fd()))
				if err != nil {
					t.Fatal(err)
				}
				if err = unix.SetNonblock(fd, true); err != nil {
					t.Fatal(err)
				}
				ready := os.NewFile(uintptr(fd), "nonblocking readiness")
				defer ready.Close()
				files := []*os.File{ready}
				for i := 4; i <= 8; i++ {
					f, err := os.CreateTemp(t.TempDir(), "fixed-input")
					if err != nil {
						t.Fatal(err)
					}
					defer f.Close()
					files = append(files, f)
				}
				if missing {
					files[2] = nil
					files[3] = nil
				}
				cmd := exec.Command(program)
				cmd.ExtraFiles = files
				cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "GOGC=off", "GOMAXPROCS=3", "GODEBUG=containermaxprocs=0,updatemaxprocs=0", "SUPERVISED_RUNTIME_EARLY=1", "SUPERVISED_RUNTIME_WARM=" + strconv.FormatBool(warm), "SUPERVISED_RUNTIME_MISSING=" + strconv.FormatBool(missing)}
				out, err := cmd.CombinedOutput()
				if err != nil || !bytes.Equal(out, []byte("runtime-alive\n")) {
					t.Fatalf("runtime lifecycle after partial refusal: %v %s", err, out)
				}
			})
		}
	}
}
