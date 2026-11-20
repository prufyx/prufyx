// SPDX-License-Identifier: AGPL-3.0-only

package localcollector

import (
	"path/filepath"

	"github.com/prufyx/prufyx/cli/internal/bundlechart"
)

// chartLabelOf reads the one chart label from the metadata.labels of a
// workload object the collector has already read. It reads exactly one key,
// takes the object's kind, namespace and name as the reference that shows the
// user where the identity came from, and touches no other label, annotation or
// field. It issues no request of its own.
func chartLabelOf(item any, kind string) (bundlechart.LabelObservation, bool) {
	labels, ok := object(at(item, "metadata", "labels"))
	if !ok {
		return bundlechart.LabelObservation{}, false
	}
	label, ok := labels[bundlechart.ChartLabel].(string)
	if !ok || label == "" {
		return bundlechart.LabelObservation{}, false
	}
	name, _ := at(item, "metadata", "name").(string)
	namespace, _ := at(item, "metadata", "namespace").(string)
	return bundlechart.LabelObservation{Kind: kind, Namespace: namespace, Name: name, Label: label}, true
}

// writeChartIdentity merges the user's declaration with the labels gathered
// from the workload reads and persists the set for one context.
func writeChartIdentity(dir string, declared []bundlechart.Declared, labels []bundlechart.LabelObservation, unread int) (bundlechart.Set, error) {
	set := bundlechart.Build(declared, labels, unread)
	return set, writeJSON(filepath.Join(dir, bundlechart.FileName), set)
}
