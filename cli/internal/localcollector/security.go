// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var envNameRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,63}$`)

func validateLocalPathsAndTools(o *Options) error {
	raw, err := readKubeconfigForSnapshot(o.Kubeconfig)
	if err != nil {
		return errors.New("An explicit readable, non-symlink private kubeconfig file is required.")
	}
	if err := validateKubeconfigSnapshotSemantics(raw); err != nil {
		wipeKubeconfigBytes(raw)
		return errors.New("The kubeconfig cannot be safely snapshotted; use absolute credential paths and a supported authentication helper form.")
	}
	o.kubeconfigSnapshot = raw
	kubectl, err := resolveKubectl(o.Kubectl)
	if err != nil {
		wipeKubeconfigBytes(o.kubeconfigSnapshot)
		o.kubeconfigSnapshot = nil
		return err
	}
	o.Kubectl = kubectl
	if info, err := os.Lstat(o.OutputRoot); err == nil && info.Mode()&os.ModeSymlink != 0 {
		wipeKubeconfigBytes(o.kubeconfigSnapshot)
		o.kubeconfigSnapshot = nil
		return errors.New("The output directory must not be a symbolic link.")
	}
	if err := os.MkdirAll(o.OutputRoot, 0o700); err != nil {
		wipeKubeconfigBytes(o.kubeconfigSnapshot)
		o.kubeconfigSnapshot = nil
		return errors.New("Cannot create output directory.")
	}
	if err := os.Chmod(o.OutputRoot, 0o700); err != nil {
		wipeKubeconfigBytes(o.kubeconfigSnapshot)
		o.kubeconfigSnapshot = nil
		return errors.New("Cannot make output directory private.")
	}
	return nil
}

// resolveKubectl resolves both an explicit path and the default PATH lookup
// before execution. Symlinks are intentionally supported for package-manager
// installations, but the final target must be a regular executable file.
func resolveKubectl(configured string) (string, error) {
	lookup := configured
	if lookup == "" {
		lookup = "kubectl"
	}
	path, err := exec.LookPath(lookup)
	if err != nil {
		return "", errors.New("A usable kubectl executable is required.")
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return "", errors.New("A usable kubectl executable is required.")
	}
	path, err = filepath.Abs(path)
	if err != nil {
		return "", errors.New("A usable kubectl executable is required.")
	}
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return "", errors.New("A usable kubectl executable is required.")
	}
	return path, nil
}

func collectorEnvironment(kubeconfig string, selected []string) ([]string, error) {
	ambient := map[string]string{}
	for _, pair := range os.Environ() {
		if i := strings.IndexByte(pair, '='); i > 0 {
			ambient[pair[:i]] = pair[i+1:]
		}
	}
	if len(selected) > 64 {
		return nil, errors.New("At most 64 --exec-env values may be forwarded.")
	}
	seen := map[string]bool{}
	for _, name := range selected {
		if !envNameRE.MatchString(name) || controlledEnvironment(name) || seen[name] {
			return nil, errors.New("A selected kubectl environment name is invalid, controlled, or duplicated.")
		}
		if _, ok := ambient[name]; !ok {
			return nil, errors.New("A selected kubectl environment variable was not present.")
		}
		seen[name] = true
	}
	for _, name := range proxyEnvironmentNames {
		if _, present := ambient[name]; present && !seen[name] {
			return nil, errors.New("An ambient proxy variable must be selected explicitly; refusing to bypass it.")
		}
	}

	env := []string{"LANG=C", "LC_ALL=C", "KUBECONFIG=" + kubeconfig}
	total := len(kubeconfig)
	for _, name := range []string{"PATH", "HOME", "USER", "TMPDIR"} {
		if value, ok := ambient[name]; ok {
			if len(value) > 65536 {
				return nil, errors.New("The selected kubectl environment exceeds the bounded size.")
			}
			total += len(value)
			env = append(env, name+"="+value)
		}
	}
	for _, name := range selected {
		value := ambient[name]
		if len(value) > 65536 {
			return nil, errors.New("The selected kubectl environment exceeds the bounded size.")
		}
		total += len(value)
		env = append(env, name+"="+value)
	}
	if total > 262144 {
		return nil, errors.New("The selected kubectl environment exceeds the bounded total size.")
	}
	return env, nil
}

var proxyEnvironmentNames = []string{
	"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
	"http_proxy", "https_proxy", "all_proxy", "no_proxy",
}

func controlledEnvironment(name string) bool {
	switch name {
	case "PATH", "HOME", "USER", "TMPDIR", "LANG", "LC_ALL", "KUBECONFIG",
		"BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "CDPATH", "GLOBIGNORE", "IFS":
		return true
	}
	return strings.HasPrefix(name, "LD_") || strings.HasPrefix(name, "DYLD_") || strings.HasPrefix(name, "PYTHON")
}

func contextDigest(key []byte, name string) string {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte("prufyx.io/context-identity/v1\x00"))
	_, _ = h.Write([]byte(name))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}
