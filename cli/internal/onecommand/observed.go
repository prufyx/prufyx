// SPDX-License-Identifier: AGPL-3.0-only

package onecommand

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
)

// Observed states what the collector actually saw in one context, so a report
// reader can tell "not observed" from "observed absent". It is derived only
// from files the collector already wrote (server-version.json,
// node-profiles.json, component-configuration-surface.json, omissions.tsv).
// It carries versions, counts and reason codes only: no namespace, workload,
// node or object names. Nothing new is collected for it.
type Observed struct {
	// KubernetesVersion is the server gitVersion; empty when not observed.
	KubernetesVersion string            `json:"kubernetesVersion"`
	Kubelets          ObservedKubelets  `json:"kubelets"`
	Components        []ObservedComp    `json:"components"`
	Omissions         []ObservedOmitted `json:"omissions"`
}

type ObservedKubelets struct {
	NodeCount int                `json:"nodeCount"`
	Min       string             `json:"min,omitempty"`
	Max       string             `json:"max,omitempty"`
	Versions  []KubeletVersionCt `json:"versions"`
}

type KubeletVersionCt struct {
	Version string `json:"version"`
	Nodes   int    `json:"nodes"`
}

type ObservedComp struct {
	ComponentID string `json:"componentId"`
	// Version is empty when the version is in conflict or unknown.
	Version string `json:"version,omitempty"`
	State   string `json:"state"`
}

type ObservedOmitted struct {
	Resource string `json:"resource"`
	Code     string `json:"code"`
	Hint     string `json:"hint"`
}

const (
	maxObservedFileBytes = 8 << 20
	maxObservedItems     = 4096
)

// readObserved never fails: a missing or unreadable source file simply leaves
// that part empty, which the report then shows as "not observed".
func readObserved(contextDir string) Observed {
	obs := Observed{Components: []ObservedComp{}, Omissions: []ObservedOmitted{}, Kubelets: ObservedKubelets{Versions: []KubeletVersionCt{}}}

	var server struct {
		GitVersion string `json:"gitVersion"`
	}
	if readJSON(filepath.Join(contextDir, "server-version.json"), &server) {
		obs.KubernetesVersion = server.GitVersion
	}

	var nodes struct {
		NodeCount int `json:"nodeCount"`
		Profiles  []struct {
			Profile struct {
				KubeletVersion string `json:"kubeletVersion"`
			} `json:"profile"`
			Count int `json:"count"`
		} `json:"profiles"`
	}
	if readJSON(filepath.Join(contextDir, "node-profiles.json"), &nodes) {
		counts := map[string]int{}
		for _, p := range nodes.Profiles {
			if p.Profile.KubeletVersion != "" && p.Count > 0 {
				counts[p.Profile.KubeletVersion] += p.Count
			}
		}
		for v, n := range counts {
			obs.Kubelets.Versions = append(obs.Kubelets.Versions, KubeletVersionCt{Version: v, Nodes: n})
		}
		sort.Slice(obs.Kubelets.Versions, func(i, j int) bool {
			return versionLess(obs.Kubelets.Versions[i].Version, obs.Kubelets.Versions[j].Version)
		})
		obs.Kubelets.NodeCount = nodes.NodeCount
		if n := len(obs.Kubelets.Versions); n > 0 {
			obs.Kubelets.Min = obs.Kubelets.Versions[0].Version
			obs.Kubelets.Max = obs.Kubelets.Versions[n-1].Version
		}
	}

	var surface struct {
		Components []struct {
			ComponentID      string  `json:"componentId"`
			ObservedVersion  *string `json:"observedVersion"`
			ObservationState string  `json:"observationState"`
		} `json:"components"`
	}
	if readJSON(filepath.Join(contextDir, "component-configuration-surface.json"), &surface) {
		for _, c := range surface.Components {
			comp := ObservedComp{ComponentID: c.ComponentID, State: c.ObservationState}
			if c.ObservedVersion != nil {
				comp.Version = *c.ObservedVersion
			}
			obs.Components = append(obs.Components, comp)
		}
		sort.Slice(obs.Components, func(i, j int) bool { return obs.Components[i].ComponentID < obs.Components[j].ComponentID })
	}

	if raw, err := currentbundle.ReadBoundedFile(filepath.Join(contextDir, "omissions.tsv"), maxObservedFileBytes); err == nil {
		for _, line := range strings.Split(string(raw), "\n") {
			fields := strings.Split(line, "\t")
			if len(fields) < 2 || fields[0] == "" || len(obs.Omissions) >= maxObservedItems {
				continue
			}
			obs.Omissions = append(obs.Omissions, ObservedOmitted{
				Resource: strings.TrimSuffix(fields[0], ".json"),
				Code:     fields[1],
				Hint:     omissionHint(strings.TrimSuffix(fields[0], ".json"), fields[1]),
			})
		}
		sort.SliceStable(obs.Omissions, func(i, j int) bool {
			if obs.Omissions[i].Resource != obs.Omissions[j].Resource {
				return obs.Omissions[i].Resource < obs.Omissions[j].Resource
			}
			return obs.Omissions[i].Code < obs.Omissions[j].Code
		})
	}
	return obs
}

func readJSON(path string, into any) bool {
	raw, err := currentbundle.ReadBoundedFile(path, maxObservedFileBytes)
	if err != nil {
		return false
	}
	return json.Unmarshal(raw, into) == nil
}

// omissionHint maps a collector reason code to a short, fixed operator hint.
// The hint never echoes anything read from the cluster.
func omissionHint(resource, code string) string {
	switch {
	case strings.Contains(code, "unsupported_not_found_api"):
		return "API not served by this cluster (component likely not installed)"
	case code == "projection_filter_rejected":
		return "the API response contained fields the collector's allow-list does not accept; please report"
	case strings.Contains(code, "authorization_rbac_forbidden"), strings.Contains(code, "unauthorized"):
		return "grant read access to " + resource + " (get/list) for the kubeconfig identity"
	case strings.Contains(code, "authentication_exec_plugin_failure"):
		return "the kubeconfig authentication helper failed; check it runs non-interactively"
	case strings.Contains(code, "invalid_kubeconfig_context"):
		return "the kubeconfig or context is invalid; check the context name and file"
	case strings.Contains(code, "tls_certificate"):
		return "TLS or certificate problem reaching the API server; check the kubeconfig CA and endpoint"
	case strings.Contains(code, "dns"):
		return "the API server host name did not resolve; check the kubeconfig endpoint"
	case strings.Contains(code, "transport_timeout_unreachable"):
		return "the API server timed out or was unreachable; check network access and retry"
	case code == "strict_json_rejected":
		return "the API response was not valid bounded JSON; please report"
	case code == "pipeline_failed":
		return "the collector pipeline failed for this read; retry, and report if it persists"
	case strings.HasPrefix(code, "kubernetes_api_read_failed"):
		return "the API read failed without a classified cause; check connectivity and read-only RBAC"
	}
	return "unclassified collector omission; please report the reason code"
}

// versionLess orders Kubernetes-style versions (v1.31.2-eks-abc) by their
// numeric major.minor.patch, falling back to string order for ties.
func versionLess(a, b string) bool {
	na, nb := versionNumbers(a), versionNumbers(b)
	for i := 0; i < 3; i++ {
		if na[i] != nb[i] {
			return na[i] < nb[i]
		}
	}
	return a < b
}

func versionNumbers(v string) [3]int {
	var out [3]int
	v = strings.TrimPrefix(v, "v")
	for i, part := range strings.SplitN(v, ".", 3) {
		end := 0
		for end < len(part) && part[end] >= '0' && part[end] <= '9' {
			end++
		}
		out[i], _ = strconv.Atoi(part[:end])
	}
	return out
}
