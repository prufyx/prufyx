// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"errors"
	"fmt"
	"os"

	"github.com/prufyx/prufyx/cli/internal/cloudeventsstructuredjson"
	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
	"github.com/prufyx/prufyx/cli/internal/spiffex509svid"
	"github.com/prufyx/prufyx/cli/internal/tikvgcpv2"
)

// ConstraintsTargetPath is the sole TUF target accepted by the generic CNCF
// knowledge profile. It is deliberately distinct from the legacy cert target.
const ConstraintsTargetPath = "knowledge/constraints.v1.json"

// SPIFFEX509SVIDTargetPath is the sole TUF target accepted by the isolated
// SPIFFE X.509-SVID conformance profile.
const SPIFFEX509SVIDTargetPath = "knowledge/spiffe-x509-svid-profile.v1.json"

// CloudEventsStructuredJSONTargetPath is the sole TUF target accepted by the
// isolated CloudEvents structured JSON conformance profile.
const CloudEventsStructuredJSONTargetPath = "knowledge/cloudevents-structured-json-profile.v1.json"

// TiKVGCPV2WIFBackupTargetPath is the sole TUF target accepted by the isolated
// TiKV planned GCS WIF full-backup preflight profile.
const TiKVGCPV2WIFBackupTargetPath = "knowledge/tikv-gcp-v2-wif-backup-profile.v1.json"

type profileID uint8

const (
	profileCertManager profileID = iota + 1
	profileConstraints
	profileSPIFFEX509SVID
	profileCloudEventsStructuredJSON
	profileTiKVGCPV2WIFBackup
	profileConstraintsProjects
)

const (
	profileMarkerAPIVersion      = "prufyx.io/knowledge-profile/v1"
	profileConstraintsMarkerName = "community-constraints"
	profileSPIFFEMarkerName      = "community-spiffe-x509-svid"
	profileCloudEventsMarkerName = "community-cloudevents-structured-json"
	profileTiKVMarkerName        = "community-tikv-gcp-v2-wif-backup"
	profileProjectsMarkerName    = "community-constraints-projects"
)

// profileSpec is intentionally private. A profile controls target identity,
// bounds, admission, and store marker; callers cannot substitute any of them.
type profileSpec struct {
	id          profileID
	targetPath  string
	maxTarget   int64
	markerName  string
	constraints bool
	split       bool
	cliName     string
	admit       AdmitFunc
}

func profileForID(id profileID) profileSpec {
	switch id {
	case profileCertManager:
		return certManagerProfile()
	case profileConstraints:
		return constraintsProfile()
	case profileSPIFFEX509SVID:
		return spiffeX509SVIDProfile()
	case profileCloudEventsStructuredJSON:
		return cloudEventsStructuredJSONProfile()
	case profileTiKVGCPV2WIFBackup:
		return tikvGCPV2WIFBackupProfile()
	case profileConstraintsProjects:
		return constraintsProjectsProfile()
	default:
		return profileSpec{}
	}
}

func certManagerProfile() profileSpec {
	return profileSpec{id: profileCertManager, targetPath: TargetPath, maxTarget: maxPackageEntry, cliName: "cert-manager", admit: nil}
}

func constraintsProfile() profileSpec {
	return profileSpec{id: profileConstraints, targetPath: ConstraintsTargetPath, maxTarget: maxPackageEntry, markerName: profileConstraintsMarkerName, constraints: true, cliName: "cncf", admit: admitConstraints}
}

func spiffeX509SVIDProfile() profileSpec {
	return profileSpec{id: profileSPIFFEX509SVID, targetPath: SPIFFEX509SVIDTargetPath, maxTarget: maxPackageEntry, markerName: profileSPIFFEMarkerName, cliName: "spiffe-x509-svid", admit: admitSPIFFEX509SVID}
}

func cloudEventsStructuredJSONProfile() profileSpec {
	return profileSpec{id: profileCloudEventsStructuredJSON, targetPath: CloudEventsStructuredJSONTargetPath, maxTarget: maxPackageEntry, markerName: profileCloudEventsMarkerName, cliName: "cloudevents-structured-json", admit: admitCloudEventsStructuredJSON}
}

func tikvGCPV2WIFBackupProfile() profileSpec {
	return profileSpec{id: profileTiKVGCPV2WIFBackup, targetPath: TiKVGCPV2WIFBackupTargetPath, maxTarget: maxPackageEntry, markerName: profileTiKVMarkerName, cliName: "tikv-gcp-v2-wif-backup", admit: admitTiKVGCPV2WIFBackup}
}

// constraintsProjectsProfile is the per-project CNCF layout: one index
// target plus one target per project, each capped at 1 MiB.
func constraintsProjectsProfile() profileSpec {
	return profileSpec{id: profileConstraintsProjects, targetPath: ConstraintsProjectsIndexTargetPath, maxTarget: maxPackageEntry, markerName: profileProjectsMarkerName, split: true, cliName: "cncf-projects", admit: admitConstraintsIndex}
}

func (p profileSpec) valid() bool {
	if p.split != (p.id == profileConstraintsProjects) {
		return false
	}
	if p.id == profileConstraintsProjects {
		return p.targetPath == ConstraintsProjectsIndexTargetPath && p.maxTarget == maxPackageEntry && !p.constraints && p.markerName == profileProjectsMarkerName && p.cliName == "cncf-projects" && p.admit != nil
	}
	if p.id == profileCertManager {
		return p.targetPath == TargetPath && p.maxTarget == maxPackageEntry && !p.constraints && p.markerName == "" && p.cliName == "cert-manager" && p.admit == nil
	}
	if p.id == profileConstraints {
		return p.targetPath == ConstraintsTargetPath && p.maxTarget == maxPackageEntry && p.constraints && p.markerName == profileConstraintsMarkerName && p.cliName == "cncf" && p.admit != nil
	}
	if p.id == profileSPIFFEX509SVID {
		return p.targetPath == SPIFFEX509SVIDTargetPath && p.maxTarget == maxPackageEntry && !p.constraints && p.markerName == profileSPIFFEMarkerName && p.cliName == "spiffe-x509-svid" && p.admit != nil
	}
	if p.id == profileCloudEventsStructuredJSON {
		return p.targetPath == CloudEventsStructuredJSONTargetPath && p.maxTarget == maxPackageEntry && !p.constraints && p.markerName == profileCloudEventsMarkerName && p.cliName == "cloudevents-structured-json" && p.admit != nil
	}
	return p.id == profileTiKVGCPV2WIFBackup && p.targetPath == TiKVGCPV2WIFBackupTargetPath && p.maxTarget == maxPackageEntry && !p.constraints && p.markerName == profileTiKVMarkerName && p.cliName == "tikv-gcp-v2-wif-backup" && p.admit != nil
}

func (p profileSpec) marked() bool { return p.markerName != "" }

type profileMarker struct {
	APIVersion string `json:"apiVersion"`
	Profile    string `json:"profile"`
	TargetPath string `json:"targetPath"`
}

func markerBytes(p profileSpec) ([]byte, error) {
	if !p.valid() || !p.marked() {
		return nil, ErrIntegrity
	}
	return marshalCanonical(profileMarker{APIVersion: profileMarkerAPIVersion, Profile: p.markerName, TargetPath: p.targetPath})
}

// checkProfileMarker is called only after the store lock is held. Generic
// import may initialize an otherwise empty root; generic open/status may not.
// Legacy cert stores remain unmarked, but reject every profile marker.
func checkProfileMarker(store *storeFS, p profileSpec, allowInitialize bool) error {
	if !p.valid() {
		return ErrIntegrity
	}
	raw, err := store.read("profile.json", 4096)
	if os.IsNotExist(err) {
		if !p.marked() {
			return nil
		}
		if !allowInitialize {
			empty, emptyErr := store.uninitialized()
			if emptyErr != nil {
				return ErrIntegrity
			}
			if empty {
				return ErrNoSelection
			}
			return ErrIntegrity
		}
		empty, emptyErr := store.uninitialized()
		if emptyErr != nil || !empty {
			return ErrIntegrity
		}
		marker, markerErr := markerBytes(p)
		if markerErr != nil {
			return markerErr
		}
		return store.write("profile.json", marker, true)
	}
	if err != nil {
		return ErrIntegrity
	}
	var marker profileMarker
	if decodeCanonicalStrict(raw, &marker) != nil || marker.APIVersion != profileMarkerAPIVersion {
		return ErrIntegrity
	}
	if p.id == profileConstraints && marker.Profile == profileProjectsMarkerName {
		return fmt.Errorf("store holds the per-project CNCF layout; use the cncf-projects profile: %w", errors.Join(ErrLayout, ErrIntegrity))
	}
	if p.split && marker.Profile == profileConstraintsMarkerName {
		return fmt.Errorf("store holds the single-target CNCF layout; use the cncf profile or a new store directory: %w", errors.Join(ErrLayout, ErrIntegrity))
	}
	if marker.Profile != p.markerName || marker.TargetPath != p.targetPath {
		return ErrIntegrity
	}
	if !p.marked() {
		return ErrIntegrity
	}
	return nil
}

func admitSPIFFEX509SVID(target []byte) (Admission, error) {
	admission, err := spiffex509svid.AdmitProfile(target)
	if err != nil {
		return Admission{}, fmt.Errorf("SPIFFE X.509-SVID target admission: %w", ErrIntegrity)
	}
	return Admission{Revision: admission.Revision, Purpose: admission.Purpose, EngineCapabilityDigest: admission.EngineCapabilityDigest, HasRule: admission.HasRule, RuleDigest: admission.RuleDigest, EvidenceExpiresAt: admission.EvidenceExpiresAt}, nil
}

func admitCloudEventsStructuredJSON(target []byte) (Admission, error) {
	admission, err := cloudeventsstructuredjson.AdmitProfile(target)
	if err != nil {
		return Admission{}, fmt.Errorf("CloudEvents structured JSON target admission: %w", ErrIntegrity)
	}
	return Admission{Revision: admission.Revision, Purpose: admission.Purpose, EngineCapabilityDigest: admission.EngineCapabilityDigest, HasRule: admission.HasRule, RuleDigest: admission.RuleDigest, EvidenceExpiresAt: admission.EvidenceExpiresAt}, nil
}

func admitTiKVGCPV2WIFBackup(target []byte) (Admission, error) {
	admission, err := tikvgcpv2.AdmitProfile(target)
	if err != nil {
		return Admission{}, fmt.Errorf("TiKV GCP v2 WIF backup target admission: %w", ErrIntegrity)
	}
	return Admission{Revision: admission.Revision, Purpose: admission.Purpose, EngineCapabilityDigest: admission.EngineCapabilityDigest, HasRule: admission.HasRule, RuleDigest: admission.RuleDigest, EvidenceExpiresAt: admission.EvidenceExpiresAt}, nil
}

func admitConstraints(target []byte) (Admission, error) {
	bundle, err := cncfcheck.ParseExternalBundle(target)
	if err != nil {
		return Admission{}, fmt.Errorf("generic target parse: %w", ErrIntegrity)
	}
	admission, err := bundle.Admission()
	if err != nil {
		return Admission{}, fmt.Errorf("generic target admission: %w", ErrIntegrity)
	}
	if admission.Revision == "" || admission.EngineCapabilityDigest == "" || admission.Purpose == "" {
		return Admission{}, fmt.Errorf("generic target admission: %w", ErrIntegrity)
	}
	return Admission{Revision: admission.Revision, Purpose: admission.Purpose, EngineCapabilityDigest: admission.EngineCapabilityDigest, HasRule: admission.HasRule, RuleDigest: admission.RuleDigest, EvidenceExpiresAt: admission.EvidenceExpiresAt}, nil
}
