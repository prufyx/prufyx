// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"strings"
	"testing"
)

const veleroBackupCRD = `{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"backups.velero.io"},"spec":{"group":"velero.io","scope":"Namespaced"}}`
const veleroRestoreCRD = `{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"restores.velero.io"},"spec":{"group":"velero.io","scope":"Namespaced"}}`
const veleroForeignCRD = `{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.private.example"},"spec":{"group":"private.example","scope":"Namespaced"}}`
const veleroServerDeployment = `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"private-server","namespace":"private-ns"},"spec":{"replicas":1}}`
const veleroNodeAgent = `{"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"private-node-agent","namespace":"private-ns"}}`
const veleroServiceAccount = `{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"private-sa","namespace":"private-ns"}}`

const veleroSelectedServer = "private-server"

func veleroPlan(items ...string) string {
	return `{"apiVersion":"v1","kind":"List","items":[` + strings.Join(items, ",") + `]}`
}

func TestPrepareVeleroUpgradePlan_BoundedDeclaredOrder(t *testing.T) {
	tests := []struct {
		name, raw, reason string
		state             State
	}{
		{"crds precede server", veleroPlan(veleroBackupCRD, veleroRestoreCRD, veleroServerDeployment), string(ReasonVeleroCRDsBeforeServer), StatePrepared},
		{"unrelated kinds do not disturb the order", veleroPlan(veleroServiceAccount, veleroBackupCRD, veleroServerDeployment, veleroNodeAgent), string(ReasonVeleroCRDsBeforeServer), StatePrepared},
		{"server precedes crds", veleroPlan(veleroServerDeployment, veleroBackupCRD), string(ReasonVeleroCRDsAfterServer), StatePrepared},
		{"one trailing crd breaks the order", veleroPlan(veleroBackupCRD, veleroServerDeployment, veleroRestoreCRD), string(ReasonVeleroCRDsAfterServer), StatePrepared},
		{"foreign crd is not a velero crd", veleroPlan(veleroForeignCRD, veleroServerDeployment), string(ReasonVeleroCRDsAbsent), StateUnknown},
		{"absent crd documents are never a pass", veleroPlan(veleroServiceAccount, veleroServerDeployment), string(ReasonVeleroCRDsAbsent), StateUnknown},
		{"missing server deployment", veleroPlan(veleroBackupCRD, veleroNodeAgent), string(ReasonVeleroServerUnresolved), StateUnknown},
		{"ambiguous server deployment", veleroPlan(veleroBackupCRD, veleroServerDeployment, veleroServerDeployment), string(ReasonVeleroServerUnresolved), StateUnknown},
		{"selected name on another kind is not the server", veleroPlan(veleroBackupCRD, `{"apiVersion":"apps/v1","kind":"DaemonSet","metadata":{"name":"private-server","namespace":"private-ns"}}`), string(ReasonVeleroServerUnresolved), StateUnknown},
		{"unreadable crd group", veleroPlan(`{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"backups.velero.io"},"spec":{}}`, veleroServerDeployment), string(ReasonVeleroInputUnsupported), StateUnknown},
		{"unnamed document", veleroPlan(veleroBackupCRD, `{"apiVersion":"apps/v1","kind":"Deployment","metadata":{}}`), string(ReasonVeleroInputUnsupported), StateUnknown},
		{"single document cannot order", veleroServerDeployment, string(ReasonVeleroCRDsAbsent), StateUnknown},
		{"empty list", `{"apiVersion":"v1","kind":"List","items":[]}`, string(ReasonVeleroInputUnsupported), StateUnknown},
		{"typed list", `{"apiVersion":"apps/v1","kind":"DeploymentList","items":[]}`, string(ReasonVeleroInputUnsupported), StateUnknown},
		{"nested list", veleroPlan(`{"apiVersion":"v1","kind":"List","items":[]}`), string(ReasonVeleroInputUnsupported), StateUnknown},
		{"non-v1 list", `{"apiVersion":"apps/v1","kind":"List","items":[` + veleroServerDeployment + `]}`, string(ReasonVeleroInputUnsupported), StateUnknown},
		{"bad list metadata", `{"apiVersion":"v1","kind":"List","metadata":{"continue":1},"items":[` + veleroBackupCRD + `,` + veleroServerDeployment + `]}`, string(ReasonVeleroInputUnsupported), StateUnknown},
		{"pagination", `{"apiVersion":"v1","kind":"List","metadata":{"remainingItemCount":1},"items":[` + veleroBackupCRD + `,` + veleroServerDeployment + `]}`, string(ReasonVeleroPagination), StateUnknown},
		{"template", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"{{ .Release.Name }}"}}]}`, string(ReasonVeleroTemplated), StateUnknown},
		{"shell substitution", `{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"${NAME}"}}]}`, string(ReasonVeleroTemplated), StateUnknown},
		{"scalar root", `"plan"`, string(ReasonVeleroInputUnsupported), StateUnknown},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareVeleroUpgradePlan([]byte(test.raw), VeleroFrom, VeleroTo, veleroSelectedServer, true)
			if err != nil || prepared.Reason != Reason(test.reason) || prepared.State != test.state {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
			if strings.Contains(string(prepared.CanonicalInputJSON), "private-") {
				t.Fatalf("canonical input retained private names: %s", prepared.CanonicalInputJSON)
			}
		})
	}
}

func TestPrepareVeleroUpgradePlan_GuardsPrecedeOrderClassification(t *testing.T) {
	ordered := veleroPlan(veleroBackupCRD, veleroServerDeployment)
	tests := []struct {
		name, from, to, server, reason string
		planOrdered                    bool
	}{
		{"unreviewed origin", "1.16.0", VeleroTo, veleroSelectedServer, string(ReasonVeleroPairUnsupported), true},
		{"unreviewed target", VeleroFrom, "1.19.0", veleroSelectedServer, string(ReasonVeleroPairUnsupported), true},
		{"plan order not declared", VeleroFrom, VeleroTo, veleroSelectedServer, string(ReasonVeleroPlanGuardUnresolved), false},
		{"server not selected", VeleroFrom, VeleroTo, "", string(ReasonVeleroPlanGuardUnresolved), true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prepared, err := PrepareVeleroUpgradePlan([]byte(ordered), test.from, test.to, test.server, test.planOrdered)
			if err != nil || prepared.State != StateUnknown || prepared.Reason != Reason(test.reason) {
				t.Fatalf("prepared=%+v err=%v", prepared, err)
			}
		})
	}
}

// The reviewed intermediate-version pair requires no facts of its own. The
// adapter still derives the same literal ordering observation there, and must
// never present that pair as anything other than the reviewed rule's input.
func TestPrepareVeleroUpgradePlan_AdmitsReviewedIntermediatePair(t *testing.T) {
	prepared, err := PrepareVeleroUpgradePlan([]byte(veleroPlan(veleroBackupCRD, veleroServerDeployment)), VeleroIntermediateFrom, VeleroTo, veleroSelectedServer, true)
	if err != nil || prepared.State != StatePrepared || prepared.Reason != ReasonVeleroCRDsBeforeServer {
		t.Fatalf("prepared=%+v err=%v", prepared, err)
	}
	canonical := string(prepared.CanonicalInputJSON)
	if !strings.Contains(canonical, `"version":"`+VeleroIntermediateFrom+`"`) || !strings.Contains(canonical, `"version":"`+VeleroTo+`"`) {
		t.Fatalf("intermediate pair not bound: %s", canonical)
	}
}

func TestPrepareVeleroUpgradePlan_RejectsRawBoundsAndMalformedJSON(t *testing.T) {
	for _, raw := range [][]byte{
		nil,
		{0xff},
		make([]byte, maxInputBytes+1),
	} {
		if _, err := PrepareVeleroUpgradePlan(raw, VeleroFrom, VeleroTo, veleroSelectedServer, true); err == nil {
			t.Fatalf("accepted raw input of %d bytes", len(raw))
		}
	}
	for _, from := range []string{"", "1.17", "v1.17.0", VeleroTo} {
		if _, err := PrepareVeleroUpgradePlan([]byte(veleroServerDeployment), from, VeleroTo, veleroSelectedServer, true); err == nil {
			t.Fatalf("accepted from version %q", from)
		}
	}
	for _, raw := range []string{
		`{"apiVersion":"v1","apiVersion":"v1","kind":"List","items":[]}`,
		`{"apiVersion":`,
	} {
		prepared, err := PrepareVeleroUpgradePlan([]byte(raw), VeleroFrom, VeleroTo, veleroSelectedServer, true)
		if err != nil || prepared.State != StateUnknown || prepared.Reason != ReasonVeleroInputUnsupported {
			t.Fatalf("raw=%q prepared=%+v err=%v", raw, prepared, err)
		}
	}
}

func TestPrepareVeleroUpgradePlan_DigestsAndOmissionsAreStable(t *testing.T) {
	plan := veleroPlan(veleroBackupCRD, veleroServerDeployment)
	first, err := PrepareVeleroUpgradePlan([]byte(plan), VeleroFrom, VeleroTo, veleroSelectedServer, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := PrepareVeleroUpgradePlan([]byte(plan), VeleroFrom, VeleroTo, veleroSelectedServer, true)
	if err != nil {
		t.Fatal(err)
	}
	if first.SourceDigest != second.SourceDigest || first.InputDigest != second.InputDigest {
		t.Fatalf("unstable digests %+v %+v", first, second)
	}
	if first.SourceDigest != digestBytes([]byte(plan)) || first.InputDigest != digestBytes(first.CanonicalInputJSON) {
		t.Fatalf("digest bindings %+v", first)
	}
	if len(first.Omissions) != 3 || first.Omissions[2] != OmissionNoWholeUpgrade {
		t.Fatalf("omissions = %v", first.Omissions)
	}
}
