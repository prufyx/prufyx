// SPDX-License-Identifier: AGPL-3.0-only

package intake

import (
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"sort"
	"testing"
)

func TestAuxiliaryDoesNotChangeWorkspace(t *testing.T) {
	dir := root(t)
	chart := "apiVersion: v2\nname: web\nversion: 1.0.0\ndependencies:\n  - name: redis\n    version: 18.1.0\n    repository: https://charts.example.test\n"
	kust := "resources:\n  - app.yaml\nimages:\n  - name: web\n    newTag: v1\n"
	typed := "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: []\n"
	templated := "apiVersion: v2\nname: ${NAME}\n"
	write(t, filepath.Join(dir, "chart", "Chart.yaml"), chart, 0o600)
	write(t, filepath.Join(dir, "chart", "values.yaml"), "replicas: 2\n", 0o600)
	write(t, filepath.Join(dir, "base", "kustomization.yaml"), kust, 0o600)
	write(t, filepath.Join(dir, "typed", "kustomization.yml"), typed, 0o600)
	write(t, filepath.Join(dir, "tpl", "Chart.yaml"), templated, 0o600)
	write(t, filepath.Join(dir, "other", "app.yaml"), fmtCM("a"), 0o600)
	w, err := Open([]string{dir}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var aux []string
	for _, d := range w.Auxiliary {
		aux = append(aux, filepath.Base(filepath.Dir(d.Source.Display))+"/"+filepath.Base(d.Source.Display))
		if d.Value == nil || d.Source.Digest == "" {
			t.Fatalf("auxiliary document is incomplete: %+v", d)
		}
	}
	want := []string{"base/kustomization.yaml", "chart/Chart.yaml"}
	if len(aux) != len(want) || aux[0] != want[0] || aux[1] != want[1] {
		t.Fatalf("auxiliary = %v, want %v", aux, want)
	}
	// The typed kustomization stays an ordinary document; no omission is
	// removed or added by the auxiliary list.
	var shaped int
	for _, o := range w.Omissions {
		switch o.Reason {
		case ReasonNotKubernetesShaped:
			shaped++
		}
	}
	if shaped != 4 { // Chart.yaml, values.yaml, kustomization.yaml, tpl/Chart.yaml
		t.Fatalf("NOT_KUBERNETES_SHAPED omissions = %d, want 4: %+v", shaped, w.Omissions)
	}
	if len(w.Documents) != 2 {
		t.Fatalf("documents = %d, want 2", len(w.Documents))
	}
	// The workspace digest depends on file bytes only.
	var digests []string
	for _, f := range w.Files {
		digests = append(digests, f.Digest)
	}
	sort.Strings(digests)
	sum := sha256.New()
	for _, d := range digests {
		sum.Write([]byte(d + "\n"))
	}
	if w.Digest != "sha256:"+hex.EncodeToString(sum.Sum(nil)) {
		t.Fatal("workspace digest changed")
	}
	// A second walk over part of the tree gives the same retained values.
	again, err := Open([]string{filepath.Join(dir, "chart"), filepath.Join(dir, "base")}, Options{})
	if err != nil || len(again.Auxiliary) != 2 {
		t.Fatalf("again = %+v, %v", again.Auxiliary, err)
	}
}

func fmtCM(name string) string {
	return "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: " + name + "\n"
}

func TestEncryptedSourcesAreListed(t *testing.T) {
	dir := root(t)
	write(t, filepath.Join(dir, "a", "secrets.enc.yaml"), "password: ENC[AES256_GCM,data:eA==,iv:eA==,tag:eA==,type:str]\nsops:\n  mac: ENC[x]\n  version: 3.8.1\n", 0o600)
	write(t, filepath.Join(dir, "a", "values.yaml"), "password: plain\nsops: not-a-block\n", 0o600)
	write(t, filepath.Join(dir, "a", "shaped.yaml"), "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: c}\nsops: {mac: x}\n", 0o600)
	write(t, filepath.Join(dir, "b", "list.yaml"), "- sops: {mac: x}\n", 0o600)
	w, err := Open([]string{dir}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Encrypted) != 1 || filepath.Base(w.Encrypted[0].Display) != "secrets.enc.yaml" || w.Encrypted[0].Digest == "" {
		t.Fatalf("encrypted = %+v", w.Encrypted)
	}
	// The listing adds nothing else: the file is still an omission and the
	// shaped document is still a document.
	var shaped int
	for _, o := range w.Omissions {
		if o.Reason == ReasonNotKubernetesShaped {
			shaped++
		}
	}
	if shaped != 3 || len(w.Documents) != 1 {
		t.Fatalf("omissions = %d, documents = %d", shaped, len(w.Documents))
	}
	for _, block := range []map[string]any{{"mac": "x"}, {"version": "3"}, {"lastmodified": "t"}} {
		if !HasSOPSMetadata(map[string]any{"sops": block}) {
			t.Fatalf("block %v not recognised", block)
		}
	}
	if HasSOPSMetadata(map[string]any{"sops": map[string]any{"other": 1}}) || HasSOPSMetadata(map[string]any{"sops": "x"}) {
		t.Fatal("a sops key without metadata was recognised")
	}
}
