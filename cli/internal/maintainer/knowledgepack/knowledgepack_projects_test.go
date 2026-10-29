// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepack

import (
	"archive/tar"
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

func splitMemberPath(dir, base string, data []byte) string {
	return fmt.Sprintf("targets/knowledge/%s/%x.%s", dir, sha256.Sum256(data), base)
}

// splitFixture writes a signed-looking per-project directory with the index
// and the named projects; mutate may change the member map before writing.
func splitFixture(t *testing.T, projects []string, mutate func(map[string][]byte)) string {
	t.Helper()
	members := map[string][]byte{
		"metadata/1.root.json": []byte("root"), "metadata/1.snapshot.json": []byte("snapshot"),
		"metadata/1.targets.json": []byte("targets"), "metadata/timestamp.json": []byte("timestamp"),
	}
	index := []byte("index")
	members[splitMemberPath("cncf", "index.v1.json", index)] = index
	for _, name := range projects {
		data := []byte("project-" + name)
		members[splitMemberPath("cncf/projects", name+".v1.json", data)] = data
	}
	if mutate != nil {
		mutate(members)
	}
	root := filepath.Join(t.TempDir(), "source")
	for name, data := range members {
		full := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestKnowledgePack_CNCFProjects_PackagesManyTargetsDeterministically(t *testing.T) {
	var names []string
	for i := 0; i < 60; i++ { // far above the 16-file single-target bound
		names = append(names, fmt.Sprintf("project-%02d", i))
	}
	root := splitFixture(t, names, nil)
	left, err := PackageDirectory(root, ProfileCNCFProjects)
	if err != nil {
		t.Fatal(err)
	}
	right, err := PackageDirectory(root, ProfileCNCFProjects)
	if err != nil || !bytes.Equal(left, right) {
		t.Fatalf("not deterministic: %v", err)
	}
	reader := tar.NewReader(bytes.NewReader(left))
	count := 0
	for {
		if _, err := reader.Next(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		count++
	}
	if count != 4+1+60 {
		t.Fatalf("members = %d", count)
	}
	// The same directory is not a valid single-target package.
	if _, err := PackageDirectory(root, "cncf"); !errors.Is(err, ErrRejected) {
		t.Fatalf("single-target profile accepted the per-project layout: %v", err)
	}
}

func TestKnowledgePack_CNCFProjects_RejectsInvalidSets(t *testing.T) {
	cases := map[string]func(map[string][]byte){
		"digest mismatch": func(m map[string][]byte) {
			for name := range m {
				if bytes.Contains([]byte(name), []byte("alpha.v1.json")) {
					m[name] = []byte("tampered")
				}
			}
		},
		"no project": func(m map[string][]byte) {
			for name := range m {
				if bytes.Contains([]byte(name), []byte("/projects/")) {
					delete(m, name)
				}
			}
		},
		"no index": func(m map[string][]byte) {
			for name := range m {
				if bytes.Contains([]byte(name), []byte("index.v1.json")) {
					delete(m, name)
				}
			}
		},
		"second index": func(m map[string][]byte) {
			data := []byte("index-2")
			m[splitMemberPath("cncf", "index.v1.json", data)] = data
		},
		"duplicate project slug": func(m map[string][]byte) {
			data := []byte("other bytes")
			m[splitMemberPath("cncf/projects", "alpha.v1.json", data)] = data
		},
		"non-community slug under community": func(m map[string][]byte) {
			data := []byte("beta")
			m[splitMemberPath("community/projects", "beta.v1.json", data)] = data
		},
		"single-target member": func(m map[string][]byte) {
			data := []byte("single")
			m[fmt.Sprintf("targets/knowledge/%x.constraints.v1.json", sha256.Sum256(data))] = data
		},
		"unknown member name": func(m map[string][]byte) {
			data := []byte("x")
			m[splitMemberPath("cncf/projects", "Bad_Name.v1.json", data)] = data
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			root := splitFixture(t, []string{"alpha"}, mutate)
			if _, err := PackageDirectory(root, ProfileCNCFProjects); !errors.Is(err, ErrRejected) {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

func TestKnowledgePack_CNCFProjects_ProjectCountBound(t *testing.T) {
	names := func(n int) []string {
		var out []string
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf("project-%04d", i))
		}
		return out
	}
	root := splitFixture(t, names(cncfcheck.MaxExternalIndexProjects), nil)
	if _, err := PackageDirectory(root, ProfileCNCFProjects); err != nil {
		t.Fatalf("rejected %d projects: %v", cncfcheck.MaxExternalIndexProjects, err)
	}
	root = splitFixture(t, names(cncfcheck.MaxExternalIndexProjects+1), nil)
	if _, err := PackageDirectory(root, ProfileCNCFProjects); !errors.Is(err, ErrRejected) {
		t.Fatalf("accepted %d projects: %v", cncfcheck.MaxExternalIndexProjects+1, err)
	}
}

func TestKnowledgePack_SingleTargetStillRejectsPerProjectDirectories(t *testing.T) {
	root := fixture(t, "cncf")
	if err := os.MkdirAll(filepath.Join(root, "targets", "knowledge", "cncf", "projects"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := PackageDirectory(root, "cncf"); !errors.Is(err, ErrRejected) {
		t.Fatalf("single-target profile accepted per-project directories: %v", err)
	}
}
