// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"encoding/json"
	"sort"
	"strings"
)

func projectPodStatus(root any, adapter adapterAssets) ([]any, error) {
	items, err := listRoot(root, 100000)
	if err != nil {
		return nil, err
	}
	type key struct {
		scope, identity, version, scheme string
		bound                            bool
	}
	type counts struct{ total, ready, restarts int }
	groups := map[key]counts{}
	for _, pod := range items {
		namespace, ok := at(pod, "metadata", "namespace").(string)
		if !ok {
			return nil, errProjection
		}
		values := []any{}
		for _, path := range [][]string{{"status", "initContainerStatuses"}, {"status", "containerStatuses"}} {
			value := at(pod, path...)
			if value == nil {
				continue
			}
			rows, ok := array(value)
			if !ok {
				return nil, errProjection
			}
			values = append(values, rows...)
		}
		for _, value := range values {
			image, ok := boundedString(at(value, "image"), 4096)
			if !ok {
				return nil, errProjection
			}
			imageID := ""
			if raw := at(value, "imageID"); raw != nil {
				var ok bool
				imageID, ok = raw.(string)
				if !ok || len(imageID) > 4096 {
					return nil, errProjection
				}
			}
			ready := false
			if raw := at(value, "ready"); raw != nil {
				var ok bool
				ready, ok = raw.(bool)
				if !ok {
					return nil, errProjection
				}
			}
			restarts := 0
			if raw := at(value, "restartCount"); raw != nil {
				number, ok := raw.(json.Number)
				if !ok {
					return nil, errProjection
				}
				n, e := number.Int64()
				if e != nil || n < 0 {
					return nil, errProjection
				}
				restarts = int(n)
			}
			identity, version, scheme, _ := publicImage(strings.TrimPrefix(strings.TrimPrefix(image, "docker-pullable://"), "containerd://"))
			component := "PRIVATE_IMAGE_IDENTITY_OMITTED"
			if found := findAdapter(adapter.Contract, identity); found != nil {
				component = found.ComponentID
			} else {
				version = nil
				scheme = "unknown"
			}
			idIdentity, _, _, _ := publicImage(strings.TrimPrefix(strings.TrimPrefix(imageID, "docker-pullable://"), "containerd://"))
			bound := component != "PRIVATE_IMAGE_IDENTITY_OMITTED" && imageID != ""
			if bound {
				found := findAdapter(adapter.Contract, idIdentity)
				bound = found != nil && found.ComponentID == component
			}
			scope := "non-system"
			if namespace == "kube-system" {
				scope = "system"
			}
			k := key{scope, component, asString(version), scheme, bound}
			v := groups[k]
			v.total++
			if ready {
				v.ready++
			}
			v.restarts += restarts
			groups[k] = v
		}
	}
	out := []any{}
	for k, v := range groups {
		var version any
		if k.version != "" {
			version = k.version
		}
		out = append(out, map[string]any{"scope": k.scope, "imageIdentity": k.identity, "observedVersion": version, "versionScheme": k.scheme, "publicImageIDBound": k.bound, "statusContainerCount": v.total, "readyContainerCount": v.ready, "restartCount": v.restarts})
	}
	sort.SliceStable(out, func(i, j int) bool {
		a, _ := json.Marshal(out[i])
		b, _ := json.Marshal(out[j])
		return string(a) < string(b)
	})
	return out, nil
}
