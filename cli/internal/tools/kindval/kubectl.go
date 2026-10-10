// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// runner executes one command and returns its output; tests substitute a
// fake. exit is the process exit status (-1 when it did not run).
type runner func(ctx context.Context, name string, args []string, stdin []byte) (stdout, stderr []byte, exit int)

// execRunner runs real processes.
func execRunner(ctx context.Context, name string, args []string, stdin []byte) ([]byte, []byte, int) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	err := cmd.Run()
	exit := 0
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			exit = ee.ExitCode()
		} else {
			exit = -1
			fmt.Fprintf(&errb, "%v", err)
		}
	}
	return out.Bytes(), errb.Bytes(), exit
}

// kube wraps kubectl against one kubeconfig.
type kube struct {
	run        runner
	kubeconfig string
}

func (k kube) args(more ...string) []string {
	return append([]string{"--kubeconfig", k.kubeconfig}, more...)
}

func (k kube) raw(ctx context.Context, path string) ([]byte, error) {
	out, errb, exit := k.run(ctx, "kubectl", k.args("get", "--raw", path), nil)
	if exit != 0 {
		return nil, fmt.Errorf("kubectl get --raw %s: exit %d: %s", path, exit, strings.TrimSpace(string(errb)))
	}
	return out, nil
}

// serverVersion reads the API server's gitVersion ("v1.32.11").
func (k kube) serverVersion(ctx context.Context) (string, error) {
	out, err := k.raw(ctx, "/version")
	if err != nil {
		return "", err
	}
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := json.Unmarshal(out, &v); err != nil {
		return "", fmt.Errorf("/version: %w", err)
	}
	return v.GitVersion, nil
}

// discover reads every served "group/version Kind" pair from discovery:
// /api and /apis for the group versions, then each group version's resource
// list. Subresources (a name with "/") are not APIs of their own.
func (k kube) discover(ctx context.Context) ([]string, error) {
	var groupVersions []string
	core, err := k.raw(ctx, "/api")
	if err != nil {
		return nil, err
	}
	var apiVersions struct {
		Versions []string `json:"versions"`
	}
	if err := json.Unmarshal(core, &apiVersions); err != nil {
		return nil, fmt.Errorf("/api: %w", err)
	}
	for _, v := range apiVersions.Versions {
		groupVersions = append(groupVersions, "/api/"+v)
	}
	groups, err := k.raw(ctx, "/apis")
	if err != nil {
		return nil, err
	}
	var groupList struct {
		Groups []struct {
			Name     string `json:"name"`
			Versions []struct {
				GroupVersion string `json:"groupVersion"`
			} `json:"versions"`
		} `json:"groups"`
	}
	if err := json.Unmarshal(groups, &groupList); err != nil {
		return nil, fmt.Errorf("/apis: %w", err)
	}
	for _, g := range groupList.Groups {
		for _, v := range g.Versions {
			groupVersions = append(groupVersions, "/apis/"+v.GroupVersion)
		}
	}
	set := map[string]bool{}
	for _, path := range groupVersions {
		out, err := k.raw(ctx, path)
		if err != nil {
			return nil, err
		}
		var list struct {
			GroupVersion string `json:"groupVersion"`
			Resources    []struct {
				Name string `json:"name"`
				Kind string `json:"kind"`
			} `json:"resources"`
		}
		if err := json.Unmarshal(out, &list); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for _, r := range list.Resources {
			if strings.Contains(r.Name, "/") || r.Kind == "" {
				continue
			}
			set[list.GroupVersion+" "+r.Kind] = true
		}
	}
	out := make([]string, 0, len(set))
	for pair := range set {
		out = append(out, pair)
	}
	sort.Strings(out)
	return out, nil
}

// snapshot takes the served-API snapshot of the cluster.
func (k kube) snapshot(ctx context.Context, line, image string, now time.Time) (Snapshot, error) {
	version, err := k.serverVersion(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	served, err := k.discover(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{Schema: SnapshotSchema, Line: line, ServerVersion: version, Image: image, TakenAt: now.UTC().Format(time.RFC3339), Served: served}, nil
}

// dryRunCreate submits a manifest with `kubectl create --dry-run=server`
// and classifies the server's answer.
func (k kube) dryRunCreate(ctx context.Context, manifest []byte) ServerTry {
	_, errb, exit := k.run(ctx, "kubectl", k.args("create", "--dry-run=server", "-f", "-"), manifest)
	return classify(exit, string(errb))
}

// classify maps a kubectl exit and message to a server outcome. The three
// messages are the ones kubectl prints when the server has no such API:
// the REST mapper's "no matches for kind", the resource-builder's "the
// server doesn't have a resource type" and the raw 404 "could not find the
// requested resource".
func classify(exit int, stderr string) ServerTry {
	msg := strings.TrimSpace(stderr)
	if exit == 0 {
		return ServerTry{Outcome: ServerAccepted}
	}
	if strings.Contains(msg, "no matches for kind") || strings.Contains(msg, "the server doesn't have a resource type") || strings.Contains(msg, "could not find the requested resource") {
		return ServerTry{Outcome: ServerNotServed, Message: firstLine(msg)}
	}
	return ServerTry{Outcome: ServerRejected, Message: firstLine(msg)}
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 400 {
		s = s[:400]
	}
	return s
}

// apply applies manifests server-side and waits for CRDs to be established.
func (k kube) apply(ctx context.Context, manifest []byte) error {
	_, errb, exit := k.run(ctx, "kubectl", k.args("apply", "--server-side", "--force-conflicts", "-f", "-"), manifest)
	if exit != 0 {
		return fmt.Errorf("kubectl apply: exit %d: %s", exit, strings.TrimSpace(string(errb)))
	}
	return nil
}

// waitEstablished waits for the named CRDs to be established. A definition
// applied a moment ago may have no status.conditions yet, which kubectl
// wait reports as an accessor error instead of waiting; that is retried.
func (k kube) waitEstablished(ctx context.Context, names []string) error {
	if len(names) == 0 {
		return nil
	}
	args := append([]string{"wait", "--for=condition=Established", "--timeout=120s", "crd"}, names...)
	var errb []byte
	var exit int
	for attempt := 0; attempt < 30; attempt++ {
		_, errb, exit = k.run(ctx, "kubectl", k.args(args...), nil)
		if exit == 0 {
			return nil
		}
		if !strings.Contains(string(errb), "accessor error") {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return fmt.Errorf("kubectl wait: exit %d: %s", exit, strings.TrimSpace(string(errb)))
}

// deleteCRDs removes the named CRDs and waits for them to go.
func (k kube) deleteCRDs(ctx context.Context, names []string) error {
	if len(names) == 0 {
		return nil
	}
	args := append([]string{"delete", "--ignore-not-found", "--wait=true", "--timeout=120s", "crd"}, names...)
	_, errb, exit := k.run(ctx, "kubectl", k.args(args...), nil)
	if exit != 0 {
		return fmt.Errorf("kubectl delete crd: exit %d: %s", exit, strings.TrimSpace(string(errb)))
	}
	return nil
}

// getCRDs reads the named CRDs back from the cluster.
func (k kube) getCRDs(ctx context.Context, names []string) ([]CRDDef, error) {
	if len(names) == 0 {
		return nil, nil
	}
	args := append([]string{"get", "-o", "json", "crd"}, names...)
	out, errb, exit := k.run(ctx, "kubectl", k.args(args...), nil)
	if exit != 0 {
		return nil, fmt.Errorf("kubectl get crd: exit %d: %s", exit, strings.TrimSpace(string(errb)))
	}
	var list struct {
		Items []json.RawMessage `json:"items"`
		Kind  string            `json:"kind"`
	}
	if err := json.Unmarshal(out, &list); err != nil {
		return nil, fmt.Errorf("kubectl get crd: %w", err)
	}
	items := list.Items
	if list.Kind == "CustomResourceDefinition" {
		items = []json.RawMessage{out}
	}
	var defs []CRDDef
	for _, item := range items {
		var obj map[string]any
		if err := json.Unmarshal(item, &obj); err != nil {
			return nil, fmt.Errorf("kubectl get crd: %w", err)
		}
		def, ok := crdFromObject(obj)
		if !ok {
			return nil, fmt.Errorf("kubectl get crd: an item is not a CustomResourceDefinition")
		}
		defs = append(defs, def)
	}
	sort.Slice(defs, func(i, j int) bool { return defs[i].Name < defs[j].Name })
	return defs, nil
}
