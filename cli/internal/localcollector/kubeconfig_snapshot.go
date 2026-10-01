// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"bytes"
	"errors"
	"io"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxKubeconfigSnapshotBytes = 8 << 20

// validateKubeconfigSnapshotSemantics rejects reference forms whose meaning
// would change when the accepted bytes move to the private snapshot. It is not
// a kubeconfig validator and deliberately leaves kubectl's broader schema
// validation to kubectl.
func validateKubeconfigSnapshotSemantics(raw []byte) error {
	if len(raw) == 0 || len(raw) > maxKubeconfigSnapshotBytes {
		return errors.New("invalid kubeconfig input")
	}
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if err := decoder.Decode(&document); err != nil || len(document.Content) != 1 {
		return errors.New("invalid kubeconfig yaml")
	}
	var trailing yaml.Node
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("multiple kubeconfig documents")
	}
	root := document.Content[0]
	if root.Kind != yaml.MappingNode || root.ShortTag() != "!!map" || !safeKubeconfigYAMLNode(root) {
		return errors.New("unsupported kubeconfig yaml")
	}
	return validateKubeconfigReferences(root)
}

func safeKubeconfigYAMLNode(node *yaml.Node) bool {
	if node == nil || node.Anchor != "" || node.Kind == yaml.AliasNode {
		return false
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.ShortTag() != "!!map" || len(node.Content)%2 != 0 {
			return false
		}
		seen := map[string]bool{}
		for i := 0; i < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" || key.Anchor != "" || seen[key.Value] || !safeKubeconfigYAMLNode(value) {
				return false
			}
			seen[key.Value] = true
		}
		return true
	case yaml.SequenceNode:
		if node.ShortTag() != "!!seq" {
			return false
		}
		for _, child := range node.Content {
			if !safeKubeconfigYAMLNode(child) {
				return false
			}
		}
		return true
	case yaml.ScalarNode:
		switch node.ShortTag() {
		case "!!str", "!!bool", "!!int", "!!float", "!!null":
			return true
		}
	}
	return false
}

func validateKubeconfigReferences(root *yaml.Node) error {
	if err := rejectKubeconfigCaseAliases(root, "clusters", "users"); err != nil {
		return err
	}
	clusters, present := kubeconfigMapValue(root, "clusters")
	if present {
		if err := validateKubeconfigEntries(clusters, "cluster", func(cluster *yaml.Node) error {
			if err := rejectKubeconfigCaseAliases(cluster, "certificate-authority"); err != nil {
				return err
			}
			return requireAbsoluteKubeconfigPath(cluster, "certificate-authority")
		}); err != nil {
			return err
		}
	}
	users, present := kubeconfigMapValue(root, "users")
	if !present {
		return nil
	}
	return validateKubeconfigEntries(users, "user", func(user *yaml.Node) error {
		if err := rejectKubeconfigCaseAliases(user, "client-certificate", "client-key", "tokenFile", "auth-provider", "exec"); err != nil {
			return err
		}
		for _, key := range []string{"client-certificate", "client-key", "tokenFile"} {
			if err := requireAbsoluteKubeconfigPath(user, key); err != nil {
				return err
			}
		}
		if _, present := kubeconfigMapValue(user, "auth-provider"); present {
			return errors.New("auth-provider is unsupported in a relocated kubeconfig")
		}
		exec, present := kubeconfigMapValue(user, "exec")
		if !present {
			return nil
		}
		if exec.Kind != yaml.MappingNode || exec.ShortTag() != "!!map" {
			return errors.New("unsupported exec configuration")
		}
		if err := rejectKubeconfigCaseAliases(exec, "command"); err != nil {
			return err
		}
		command, present := kubeconfigMapValue(exec, "command")
		if !present || command.Kind != yaml.ScalarNode || command.ShortTag() != "!!str" {
			return errors.New("unsupported exec command")
		}
		return validateExecCommand(command.Value)
	})
}

func validateKubeconfigEntries(entries *yaml.Node, field string, validate func(*yaml.Node) error) error {
	if entries.Kind != yaml.SequenceNode || entries.ShortTag() != "!!seq" {
		return errors.New("unsupported kubeconfig entries")
	}
	for _, entry := range entries.Content {
		if entry.Kind != yaml.MappingNode || entry.ShortTag() != "!!map" {
			return errors.New("unsupported kubeconfig entry")
		}
		if err := rejectKubeconfigCaseAliases(entry, field); err != nil {
			return err
		}
		value, present := kubeconfigMapValue(entry, field)
		if !present {
			continue
		}
		if value.Kind != yaml.MappingNode || value.ShortTag() != "!!map" {
			return errors.New("unsupported kubeconfig entry")
		}
		if err := validate(value); err != nil {
			return err
		}
	}
	return nil
}

func rejectKubeconfigCaseAliases(mapping *yaml.Node, names ...string) error {
	for i := 0; i < len(mapping.Content); i += 2 {
		key := mapping.Content[i].Value
		for _, name := range names {
			if key != name && strings.EqualFold(key, name) {
				return errors.New("noncanonical kubeconfig key")
			}
		}
	}
	return nil
}

func requireAbsoluteKubeconfigPath(mapping *yaml.Node, key string) error {
	value, present := kubeconfigMapValue(mapping, key)
	if !present {
		return nil
	}
	if value.Kind != yaml.ScalarNode || value.ShortTag() != "!!str" || value.Value == "" || !filepath.IsAbs(value.Value) {
		return errors.New("relative kubeconfig reference")
	}
	return nil
}

func validateExecCommand(command string) error {
	if command == "" || strings.TrimSpace(command) != command || strings.IndexByte(command, 0) >= 0 {
		return errors.New("unsupported exec command")
	}
	if strings.ContainsAny(command, `/\\`) && !filepath.IsAbs(command) {
		return errors.New("relative exec command")
	}
	if command == "." || command == ".." {
		return errors.New("relative exec command")
	}
	return nil
}

func kubeconfigMapValue(mapping *yaml.Node, wanted string) (*yaml.Node, bool) {
	for i := 0; i < len(mapping.Content); i += 2 {
		if mapping.Content[i].Value == wanted {
			return mapping.Content[i+1], true
		}
	}
	return nil, false
}

func wipeKubeconfigBytes(raw []byte) {
	for i := range raw {
		raw[i] = 0
	}
}
