// SPDX-License-Identifier: AGPL-3.0-only

// Package certmanagervalues checks one curated, source-backed predicate for an
// exact cert-manager chart transition. It is not a JSON Schema implementation.
package certmanagervalues

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"unicode/utf8"

	"github.com/prufyx/prufyx/cli/internal/currentbundle"
)

const (
	CurrentVersion             = "1.20.3"
	TargetVersion              = "1.21.1"
	CurrentChartDigest         = "sha256:ef5cf71fc9494e8b06b2f7450e9e31fcb6b78bca1af415f6e2149e744e98faa2"
	TargetChartDigest          = "sha256:15c0b46d9006ce8eb9ff14d1bf54d1bbfcc587bb9e24cd9fe186fb8fec56af1f"
	SourceContractDigest       = "sha256:6e40f1fdca0ba2587ca64447624557b271aa86b4cd4582a2e12c9acb6b843739"
	LatestTargetVersion        = "1.21.2"
	LatestTargetChartDigest    = "sha256:634dce9c13b56677a2c05e2ab76c312d0be2664022d5dd05815da67e1fd5f610"
	LatestSourceContractDigest = "sha256:c45dfe0ea426db2b7f2d938f19bd80ae08f0e97817d780554b9614c5401835a6"
	maxValuesBytes             = 1 << 20
	maxDepth                   = 32
	maxMembers                 = 4096
	maxArrayItems              = 2048
	maxStringBytes             = 64 << 10
)

var (
	ErrInvalid   = errors.New("invalid cert-manager values input")
	ErrIntegrity = errors.New("cert-manager values integrity mismatch")
	digestRE     = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	versionRE    = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$`)
)

//go:embed source-contract-v1.json
var contractFS embed.FS

//go:embed source-contract-v1-latest.json
var latestContractFS embed.FS

var removedPaths = []string{
	"prometheus.servicemonitor.path",
	"prometheus.servicemonitor.targetPort",
	"prometheus.podmonitor.path",
}

type Artifact struct {
	digest        string
	matches       []string
	shapeResolved bool
	seal          *artifactSeal
}
type artifactSeal struct{}

type Request struct {
	Values             Artifact
	From               string
	To                 string
	CurrentChartDigest string
	TargetChartDigest  string
	SchemaValidation   string
}

type Claim struct {
	Status      string `json:"status"`
	ReasonCode  string `json:"reasonCode"`
	Reason      string `json:"reason"`
	Remediation string `json:"remediation"`
}
type Transition struct {
	Component                  string `json:"component"`
	DeclaredTransitionState    string `json:"declaredTransitionState"`
	ReviewedFrom               string `json:"reviewedFrom"`
	ReviewedTo                 string `json:"reviewedTo"`
	CurrentChartManifestDigest string `json:"currentChartManifestDigest"`
	TargetChartManifestDigest  string `json:"targetChartManifestDigest"`
	IdentityAssumption         string `json:"identityAssumption"`
}
type Policy struct {
	SchemaValidation string `json:"schemaValidation"`
	Meaning          string `json:"meaning"`
}
type Inputs struct {
	ValuesDigest            string `json:"valuesDigest"`
	KnowledgeRevisionDigest string `json:"knowledgeRevisionDigest"`
}
type Source struct {
	ID            string   `json:"id"`
	URL           string   `json:"url"`
	ContentDigest string   `json:"contentDigest"`
	Spans         []string `json:"spans,omitempty"`
}
type Truth struct {
	Offline                   bool `json:"offline"`
	NetworkUsed               bool `json:"networkUsed"`
	ClusterOperationUsed      bool `json:"clusterOperationUsed"`
	FullTargetSchemaEvaluated bool `json:"fullTargetSchemaEvaluated"`
	WholeUpgradeEvaluated     bool `json:"wholeUpgradeEvaluated"`
}
type Report struct {
	APIVersion   string     `json:"apiVersion"`
	Kind         string     `json:"kind"`
	Status       string     `json:"status"`
	Assessment   string     `json:"assessment"`
	Question     string     `json:"question"`
	Scope        string     `json:"scope"`
	Transition   Transition `json:"transition"`
	Inputs       Inputs     `json:"inputs"`
	Policy       Policy     `json:"policy"`
	Claim        Claim      `json:"claim"`
	MatchedPaths []string   `json:"matchedPaths"`
	Sources      []Source   `json:"sources"`
	Omissions    []string   `json:"omissions"`
	Truth        Truth      `json:"truth"`
	seal         *reportSeal
	hash         string
}
type reportSeal struct{}

type contractDocument struct {
	Schema    string `json:"schema"`
	Component string `json:"component"`
	Current   struct {
		Version             string `json:"version"`
		ChartManifestDigest string `json:"chartManifestDigest"`
	} `json:"current"`
	Target struct {
		Version             string `json:"version"`
		ChartManifestDigest string `json:"chartManifestDigest"`
	} `json:"target"`
	RemovedPaths []string `json:"removedPaths"`
	Sources      []Source `json:"sources"`
}

type latestContractDocument struct {
	Schema    string `json:"schema"`
	Component string `json:"component"`
	Target    struct {
		Version             string `json:"version"`
		ChartManifestDigest string `json:"chartManifestDigest"`
		TagCommit           string `json:"tagCommit"`
	} `json:"target"`
	Transitions []struct {
		Current struct {
			Version             string `json:"version"`
			ChartManifestDigest string `json:"chartManifestDigest"`
			TagCommit           string `json:"tagCommit"`
		} `json:"current"`
		Target struct {
			Version             string `json:"version"`
			ChartManifestDigest string `json:"chartManifestDigest"`
			TagCommit           string `json:"tagCommit"`
		} `json:"target"`
	} `json:"transitions"`
	OriginChartManifests []struct {
		Version       string `json:"version"`
		URL           string `json:"url"`
		Revision      string `json:"revision"`
		ContentDigest string `json:"contentDigest"`
	} `json:"originChartManifests"`
	RemovedPaths []string `json:"removedPaths"`
	Sources      []Source `json:"sources"`
}

// ReadArtifact admits a private values file using the repository's reviewed
// descriptor-relative, no-follow bounded reader. Relative paths are allowed.
func ReadArtifact(path, expectedDigest string) (Artifact, error) {
	raw, err := readPrivateValues(path)
	if err != nil {
		return Artifact{}, err
	}
	return ParseArtifact(raw, expectedDigest)
}

func readPrivateValues(path string) ([]byte, error) {
	raw, info, err := currentbundle.ReadBoundedFileInfo(path, maxValuesBytes)
	if err != nil {
		if errors.Is(err, currentbundle.ErrIntegrity) {
			return nil, fmt.Errorf("values file identity changed: %w", ErrIntegrity)
		}
		return nil, fmt.Errorf("values file admission: %w", ErrInvalid)
	}
	if info == nil || !privateReadable(info) {
		return nil, fmt.Errorf("values file permission contract: %w", ErrInvalid)
	}
	return raw, nil
}

func privateReadable(info os.FileInfo) bool {
	mode := info.Mode().Perm()
	return info.Mode().IsRegular() && mode&0o400 != 0 && mode&0o077 == 0
}

// ParseArtifact validates bounded JSON and retains only the digest, the three
// curated path matches, and whether the relevant parent shapes were objects.
func ParseArtifact(raw []byte, expectedDigest string) (Artifact, error) {
	digest, root, err := parseValuesRoot(raw, expectedDigest)
	if err != nil {
		return Artifact{}, err
	}
	matches, resolved := inspectPaths(root, removedPaths)
	return Artifact{digest: digest, matches: matches, shapeResolved: resolved, seal: &artifactSeal{}}, nil
}

func parseValuesRoot(raw []byte, expectedDigest string) (string, map[string]json.RawMessage, error) {
	if len(raw) == 0 || len(raw) > maxValuesBytes || !utf8.Valid(raw) {
		return "", nil, fmt.Errorf("values bytes: %w", ErrInvalid)
	}
	digest := digestBytes(raw)
	if expectedDigest != "" {
		if len(expectedDigest) == 64 {
			expectedDigest = "sha256:" + expectedDigest
		}
		if !digestRE.MatchString(expectedDigest) || digest != expectedDigest {
			return "", nil, fmt.Errorf("values digest: %w", ErrIntegrity)
		}
	}
	if err := validateJSON(raw); err != nil {
		return "", nil, fmt.Errorf("values JSON: %w", ErrInvalid)
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(raw, &root) != nil || root == nil {
		return "", nil, fmt.Errorf("values root object: %w", ErrInvalid)
	}
	return digest, root, nil
}

func inspectPaths(root map[string]json.RawMessage, paths []string) ([]string, bool) {
	if len(paths) == 0 {
		return []string{}, true
	}
	promRaw, ok := root["prometheus"]
	if !ok {
		return []string{}, true
	}
	var prom map[string]json.RawMessage
	if json.Unmarshal(promRaw, &prom) != nil || prom == nil {
		return []string{}, false
	}
	matches := make([]string, 0, len(paths))
	for _, parentName := range []string{"servicemonitor", "podmonitor"} {
		prefix := "prometheus." + parentName + "."
		selected := false
		for _, path := range paths {
			if len(path) > len(prefix) && path[:len(prefix)] == prefix {
				selected = true
				break
			}
		}
		if !selected {
			continue
		}
		raw, present := prom[parentName]
		if !present {
			continue
		}
		var parent map[string]json.RawMessage
		if json.Unmarshal(raw, &parent) != nil || parent == nil {
			return []string{}, false
		}
		for _, path := range paths {
			if len(path) <= len(prefix) || path[:len(prefix)] != prefix {
				continue
			}
			if _, present := parent[path[len(prefix):]]; present {
				matches = append(matches, path)
			}
		}
	}
	return matches, true
}

func Evaluate(req Request) (Report, error) {
	contract, err := verifiedContractFor(req.From, req.To)
	if err != nil {
		return Report{}, err
	}
	if req.Values.seal == nil || !digestRE.MatchString(req.Values.digest) {
		return Report{}, fmt.Errorf("values capability: %w", ErrIntegrity)
	}
	if len(req.From) > 32 || len(req.To) > 32 || !versionRE.MatchString(req.From) || !versionRE.MatchString(req.To) {
		return Report{}, fmt.Errorf("chart version syntax: %w", ErrInvalid)
	}
	if req.SchemaValidation == "" {
		req.SchemaValidation = "required"
	}
	if req.SchemaValidation != "required" && req.SchemaValidation != "disabled" {
		return Report{}, fmt.Errorf("schema validation policy: %w", ErrInvalid)
	}
	reviewed := req.From == contract.Current.Version && req.To == contract.Target.Version
	knowledgeDigest := SourceContractDigest
	if contract.Target.Version == LatestTargetVersion {
		knowledgeDigest = LatestSourceContractDigest
	}
	if req.CurrentChartDigest != "" && req.CurrentChartDigest != contract.Current.ChartManifestDigest {
		return Report{}, fmt.Errorf("current chart digest assertion: %w", ErrIntegrity)
	}
	if req.TargetChartDigest != "" && req.TargetChartDigest != contract.Target.ChartManifestDigest {
		return Report{}, fmt.Errorf("target chart digest assertion: %w", ErrIntegrity)
	}
	claim := removedMonitorClaim(req.Values.shapeResolved, req.Values.matches, req.SchemaValidation, len(removedPaths), "/metrics", "http-metrics")
	transitionState := "exact_reviewed"
	identityAssumption := "declared versions select the reviewed official charts; this report does not prove either chart is the user's deployed artifact"
	if !reviewed {
		transitionState = "unsupported"
		identityAssumption = "the declared transition is outside this reviewed knowledge revision"
		claim = Claim{Status: "UNKNOWN", ReasonCode: "CERT_MANAGER_TRANSITION_NOT_REVIEWED", Reason: "the declared semantic-version transition is not covered by this knowledge revision", Remediation: "use one exact catalog transition (1.20.3 to 1.21.1, or 1.20.3/1.19.6/1.18.6/1.17.4/1.16.5 to 1.21.2) or obtain a reviewed source contract for the intended versions"}
	}
	question := "Does the exact proposed merged values object contain any of the three curated monitoring keys removed by cert-manager 1.21.1?"
	if contract.Target.Version == LatestTargetVersion {
		question = fmt.Sprintf("Does the exact proposed merged values object contain any of the three curated monitoring keys rejected by the target cert-manager %s chart?", contract.Target.Version)
	}
	report := Report{APIVersion: "prufyx.io/cert-manager-removed-monitor-values-assessment/v1alpha1", Kind: "CertManagerRemovedMonitorValuesAssessment", Status: "CANDIDATE_ONLY", Assessment: "UNKNOWN", Question: question, Scope: "presence of three curated removed values only; not full Helm schema validation, runtime behavior, or whole-upgrade compatibility", Transition: Transition{Component: contract.Component, DeclaredTransitionState: transitionState, ReviewedFrom: contract.Current.Version, ReviewedTo: contract.Target.Version, CurrentChartManifestDigest: contract.Current.ChartManifestDigest, TargetChartManifestDigest: contract.Target.ChartManifestDigest, IdentityAssumption: identityAssumption}, Inputs: Inputs{ValuesDigest: req.Values.digest, KnowledgeRevisionDigest: knowledgeDigest}, Policy: Policy{SchemaValidation: req.SchemaValidation, Meaning: "required means Helm target schema rejection is enforced; disabled means removed overrides may render but are ignored by target templates"}, Claim: claim, MatchedPaths: append([]string(nil), req.Values.matches...), Sources: append([]Source(nil), contract.Sources...), Omissions: []string{"FULL_TARGET_HELM_SCHEMA_NOT_EVALUATED", "RUNTIME_BEHAVIOR_NOT_EVALUATED", "WHOLE_UPGRADE_COMPATIBILITY_NOT_EVALUATED"}, Truth: Truth{Offline: true}}
	return issue(report), nil
}

func removedMonitorClaim(shapeResolved bool, matches []string, schemaValidation string, pathCount int, metricsPath, metricsPortName string) Claim {
	claim := Claim{Status: "PASS", ReasonCode: "CERT_MANAGER_REMOVED_MONITOR_VALUES_ABSENT", Reason: fmt.Sprintf("none of the %s curated removed monitor values is present", countName(pathCount)), Remediation: "run full Helm schema validation and the remaining upgrade checks before deciding compatibility"}
	if !shapeResolved {
		claim = Claim{Status: "UNKNOWN", ReasonCode: "CERT_MANAGER_MONITOR_VALUES_SHAPE_UNRESOLVED", Reason: "a relevant prometheus or monitor parent is not a JSON object", Remediation: "provide the exact merged values with prometheus and monitor parents represented as JSON objects"}
	}
	if len(matches) > 0 {
		if schemaValidation == "required" {
			claim = Claim{Status: "BLOCKED", ReasonCode: "CERT_MANAGER_REMOVED_MONITOR_VALUE_PRESENT", Reason: "the exact proposed values contain a curated key rejected by the target chart schema", Remediation: fmt.Sprintf("remove every matched key; then verify that %s and %s satisfy the intended scrape integration", metricsPath, metricsPortName)}
		} else {
			claim = Claim{Status: "ATTENTION", ReasonCode: "CERT_MANAGER_REMOVED_MONITOR_VALUE_IGNORED_WITH_SCHEMA_VALIDATION_DISABLED", Reason: "schema validation is disabled and the target templates ignore the curated removed override", Remediation: fmt.Sprintf("remove every matched key and re-enable schema validation; then verify that %s and %s satisfy the intended scrape integration", metricsPath, metricsPortName)}
		}
	}
	return claim
}

func countName(count int) string {
	words := [...]string{"zero", "one", "two", "three"}
	if count >= 0 && count < len(words) {
		return words[count]
	}
	return fmt.Sprintf("%d", count)
}

func MarshalReport(report Report) ([]byte, error) {
	if report.seal == nil {
		return nil, fmt.Errorf("report capability: %w", ErrIntegrity)
	}
	raw, err := json.Marshal(report)
	if err != nil || digestBytes(raw) != report.hash {
		return nil, fmt.Errorf("report mutation: %w", ErrIntegrity)
	}
	return raw, nil
}

// Replay re-evaluates the explicit original artifact and compares canonical
// report bytes. This detects drift; it does not authenticate authorship.
func Replay(req Request, receipt []byte) (Report, error) {
	if bytes.HasSuffix(receipt, []byte("\n")) {
		receipt = receipt[:len(receipt)-1]
	}
	report, err := Evaluate(req)
	if err != nil {
		return Report{}, err
	}
	raw, err := MarshalReport(report)
	if err != nil {
		return Report{}, err
	}
	if !bytes.Equal(raw, receipt) {
		return Report{}, fmt.Errorf("replay receipt mismatch: %w", ErrIntegrity)
	}
	return report, nil
}

func issue(report Report) Report {
	raw, _ := json.Marshal(report)
	report.seal = &reportSeal{}
	report.hash = digestBytes(raw)
	return report
}
func digestBytes(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func verifiedContract() (contractDocument, error) {
	return verifiedContractFile(contractFS, "source-contract-v1.json", SourceContractDigest, CurrentVersion, TargetVersion, CurrentChartDigest, TargetChartDigest)
}

func verifiedContractFor(from, to string) (contractDocument, error) {
	if to == LatestTargetVersion && latestSourceVersion(from) {
		return verifiedLatestContract(from, to)
	}
	return verifiedContract()
}

func latestSourceVersion(version string) bool {
	switch version {
	case "1.20.3", "1.19.6", "1.18.6", "1.17.4", "1.16.5":
		return true
	default:
		return false
	}
}

func verifiedLatestContract(from, to string) (contractDocument, error) {
	raw, err := latestContractFS.ReadFile("source-contract-v1-latest.json")
	if err != nil || digestBytes(raw) != LatestSourceContractDigest {
		return contractDocument{}, fmt.Errorf("latest source contract bytes: %w", ErrIntegrity)
	}
	var latest latestContractDocument
	if json.Unmarshal(raw, &latest) != nil || latest.Schema != "prufyx.io/cert-manager-removed-monitor-values-source-contract/v1" || latest.Component == "" || latest.Target.Version != LatestTargetVersion || latest.Target.ChartManifestDigest != LatestTargetChartDigest || !validGitRevision(latest.Target.TagCommit) || len(latest.Transitions) != 5 || len(latest.OriginChartManifests) != 5 || len(latest.RemovedPaths) != len(removedPaths) || len(latest.Sources) != 4 {
		return contractDocument{}, fmt.Errorf("latest source contract fields: %w", ErrIntegrity)
	}
	for i := range removedPaths {
		if latest.RemovedPaths[i] != removedPaths[i] {
			return contractDocument{}, fmt.Errorf("latest source contract paths: %w", ErrIntegrity)
		}
	}
	for _, source := range latest.Sources {
		if source.ID == "" || source.URL == "" || !digestRE.MatchString(source.ContentDigest) {
			return contractDocument{}, fmt.Errorf("latest source contract evidence: %w", ErrIntegrity)
		}
	}
	originByVersion := make(map[string]struct {
		digest, revision string
	}, len(latest.OriginChartManifests))
	for _, origin := range latest.OriginChartManifests {
		if !versionRE.MatchString(origin.Version) || origin.URL == "" || !validGitRevision(origin.Revision) || !digestRE.MatchString(origin.ContentDigest) {
			return contractDocument{}, fmt.Errorf("latest origin chart evidence: %w", ErrIntegrity)
		}
		if _, exists := originByVersion[origin.Version]; exists {
			return contractDocument{}, fmt.Errorf("duplicate latest origin chart evidence: %w", ErrIntegrity)
		}
		originByVersion[origin.Version] = struct {
			digest, revision string
		}{origin.ContentDigest, origin.Revision}
	}
	var selected contractDocument
	found := false
	seenTransitions := make(map[string]bool, len(latest.Transitions))
	for _, transition := range latest.Transitions {
		origin, originExists := originByVersion[transition.Current.Version]
		if seenTransitions[transition.Current.Version] || !originExists || !validGitRevision(transition.Current.TagCommit) || transition.Current.TagCommit != origin.revision || transition.Current.ChartManifestDigest != origin.digest || !validGitRevision(transition.Target.TagCommit) || transition.Target.TagCommit != latest.Target.TagCommit || transition.Target.Version != LatestTargetVersion || transition.Target.ChartManifestDigest != LatestTargetChartDigest {
			return contractDocument{}, fmt.Errorf("latest transition identity: %w", ErrIntegrity)
		}
		seenTransitions[transition.Current.Version] = true
		if transition.Current.Version == from && transition.Target.Version == to {
			selected = contractDocument{Schema: latest.Schema, Component: latest.Component, Current: struct {
				Version             string `json:"version"`
				ChartManifestDigest string `json:"chartManifestDigest"`
			}{Version: transition.Current.Version, ChartManifestDigest: transition.Current.ChartManifestDigest}, Target: struct {
				Version             string `json:"version"`
				ChartManifestDigest string `json:"chartManifestDigest"`
			}{Version: transition.Target.Version, ChartManifestDigest: transition.Target.ChartManifestDigest}, RemovedPaths: latest.RemovedPaths, Sources: latest.Sources}
			found = true
		}
	}
	if found && len(seenTransitions) == len(originByVersion) {
		return selected, nil
	}
	return contractDocument{}, fmt.Errorf("latest transition not found: %w", ErrIntegrity)
}

func validGitRevision(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func verifiedContractFile(files embed.FS, name, expectedDigest, currentVersion, targetVersion, currentChartDigest, targetChartDigest string) (contractDocument, error) {
	raw, err := files.ReadFile(name)
	if err != nil || digestBytes(raw) != expectedDigest {
		return contractDocument{}, fmt.Errorf("source contract bytes: %w", ErrIntegrity)
	}
	var c contractDocument
	if json.Unmarshal(raw, &c) != nil || c.Schema != "prufyx.io/cert-manager-removed-monitor-values-source-contract/v1" || c.Current.Version != currentVersion || c.Target.Version != targetVersion || c.Current.ChartManifestDigest != currentChartDigest || c.Target.ChartManifestDigest != targetChartDigest || len(c.RemovedPaths) != len(removedPaths) || len(c.Sources) != 4 {
		return contractDocument{}, fmt.Errorf("source contract fields: %w", ErrIntegrity)
	}
	for i := range removedPaths {
		if c.RemovedPaths[i] != removedPaths[i] {
			return contractDocument{}, fmt.Errorf("source contract paths: %w", ErrIntegrity)
		}
	}
	for _, source := range c.Sources {
		if source.ID == "" || source.URL == "" || !digestRE.MatchString(source.ContentDigest) {
			return contractDocument{}, fmt.Errorf("source contract evidence: %w", ErrIntegrity)
		}
	}
	return c, nil
}

func validateJSON(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consume(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return ErrInvalid
	}
	return nil
}

func consume(decoder *json.Decoder, depth int) error {
	if depth > maxDepth {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalid
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			seen := map[string]struct{}{}
			count := 0
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return ErrInvalid
				}
				key, ok := keyToken.(string)
				if !ok || len(key) > maxStringBytes {
					return ErrInvalid
				}
				if _, duplicate := seen[key]; duplicate {
					return ErrInvalid
				}
				seen[key] = struct{}{}
				count++
				if count > maxMembers {
					return ErrInvalid
				}
				if err := consume(decoder, depth+1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return ErrInvalid
			}
		case '[':
			count := 0
			for decoder.More() {
				count++
				if count > maxArrayItems {
					return ErrInvalid
				}
				if err := consume(decoder, depth+1); err != nil {
					return err
				}
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return ErrInvalid
			}
		default:
			return ErrInvalid
		}
	case string:
		if len(value) > maxStringBytes {
			return ErrInvalid
		}
	case nil, bool, json.Number:
	default:
		return ErrInvalid
	}
	return nil
}
