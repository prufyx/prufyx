// SPDX-License-Identifier: AGPL-3.0-only

// Package supportinventory derives the public support inventory from reviewed inputs.
package supportinventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/prufyx/prufyx/cli/internal/checkroutemetadata"
)

const Schema = "prufyx.io/community-support-inventory/v1alpha1"
const selectedSchema = "prufyx.io/selected-source-records/v1"
const maxCNCFPrepareSourceBytes = 1 << 20

var ErrInvalid = errors.New("invalid support inventory input")
var projectRE = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
var digestRE = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
var versionRE = regexp.MustCompile(`^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$`)
var commitRE = regexp.MustCompile(`^[0-9a-f]{40}$`)
var idRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,159}$`)
var sourceKinds = map[string]bool{"changelog": true, "helm_chart": true, "migration_guide": true, "release_note": true, "repository_metadata": true, "source_code": true}

type Config struct {
	Rules, Landscape, CertContract, PrometheusContract string
	SPIFFEProfile, CloudEventsProfile, TiKVProfile     string
	CNCFPrepareSource, SelectedSourceManifest          string
	ProjectRules, ProjectRegistry                      string
	// ReadFile, when set, reads every input instead of the file system:
	// it is given the paths above and at most limit bytes are needed. A
	// missing file must be reported with an error matching
	// os.ErrNotExist.
	ReadFile func(path string, limit int64) ([]byte, error)
}

// maxInputBytes bounds an inventory input read through Config.ReadFile.
const maxInputBytes = 16 << 20

func (cfg Config) readInput(path string, limit int64) ([]byte, error) {
	if cfg.ReadFile != nil {
		return cfg.ReadFile(path, limit)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, limit+1))
}

type loaded struct {
	value  map[string]any
	digest string
}
type identity struct{ name, repository string }

func invalid(message string) error { return fmt.Errorf("%s: %w", message, ErrInvalid) }
func require(ok bool, message string) error {
	if !ok {
		return invalid(message)
	}
	return nil
}

func object(value any) (map[string]any, bool) { v, ok := value.(map[string]any); return v, ok }
func array(value any) ([]any, bool)           { v, ok := value.([]any); return v, ok }
func stringValue(value any) (string, bool)    { v, ok := value.(string); return v, ok }
func integer(value any) (int, bool) {
	v, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	n, err := strconv.Atoi(v.String())
	return n, err == nil
}
func exactKeys(value map[string]any, keys ...string) bool {
	if len(value) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}

func decodeStrict(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	value, err := decodeValue(dec)
	if err != nil {
		return nil, err
	}
	if token, err := dec.Token(); err != io.EOF || token != nil {
		return nil, invalid("trailing JSON value")
	}
	return value, nil
}

func decodeValue(dec *json.Decoder) (any, error) {
	token, err := dec.Token()
	if err != nil {
		return nil, invalid("cannot parse JSON")
	}
	switch t := token.(type) {
	case json.Delim:
		switch t {
		case '{':
			result := map[string]any{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, invalid("cannot parse object key")
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, invalid("non-string object key")
				}
				if _, exists := result[key]; exists {
					return nil, invalid("duplicate JSON object field")
				}
				value, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				result[key] = value
			}
			if end, err := dec.Token(); err != nil || end != json.Delim('}') {
				return nil, invalid("unterminated object")
			}
			return result, nil
		case '[':
			var result []any
			for dec.More() {
				value, err := decodeValue(dec)
				if err != nil {
					return nil, err
				}
				result = append(result, value)
			}
			if end, err := dec.Token(); err != nil || end != json.Delim(']') {
				return nil, invalid("unterminated array")
			}
			return result, nil
		}
	}
	return token, nil
}

func (cfg Config) load(path string) (loaded, error) {
	raw, err := cfg.readInput(path, maxInputBytes)
	if err != nil {
		return loaded{}, fmt.Errorf("read inventory input: %w", err)
	}
	if len(raw) > maxInputBytes {
		return loaded{}, invalid("inventory input exceeds the bounded size")
	}
	value, err := decodeStrict(raw)
	if err != nil {
		return loaded{}, err
	}
	obj, ok := object(value)
	if !ok {
		return loaded{}, invalid("inventory input must be an object")
	}
	return loaded{obj, fmt.Sprintf("sha256:%x", sha256.Sum256(raw))}, nil
}

func validText(value any, maximum int) (string, error) {
	text, ok := stringValue(value)
	if !ok || len(text) == 0 || len(text) > maximum {
		return "", invalid("invalid bounded text")
	}
	for _, c := range text {
		if c < 32 || c == 127 {
			return "", invalid("invalid control character")
		}
	}
	return text, nil
}

func httpsURL(value any, githubRepo bool) (string, error) {
	raw, err := validText(value, 2048)
	if err != nil || strings.ContainsAny(raw, "<> \t\r\n") {
		return "", invalid("invalid HTTPS URL")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", invalid("invalid HTTPS URL")
	}
	if githubRepo {
		parts := strings.FieldsFunc(u.Path, func(r rune) bool { return r == '/' })
		if u.Host != "github.com" || len(parts) != 2 {
			return "", invalid("invalid GitHub repository URL")
		}
	}
	return raw, nil
}

func immutableURL(value any) (string, string, error) {
	raw, err := httpsURL(value, false)
	if err != nil {
		return "", "", err
	}
	u, _ := url.Parse(raw)
	parts := strings.FieldsFunc(u.Path, func(r rune) bool { return r == '/' })
	if u.Host == "github.com" && len(parts) >= 5 && parts[2] == "blob" && commitRE.MatchString(parts[3]) {
		return raw, parts[3], nil
	}
	if u.Host == "raw.githubusercontent.com" && len(parts) >= 4 && commitRE.MatchString(parts[2]) {
		return raw, parts[2], nil
	}
	return "", "", invalid("invalid immutable GitHub URL")
}

func sourceSpans(value any) ([]any, error) {
	items, ok := array(value)
	if !ok || len(items) == 0 || len(items) > 32 {
		return nil, invalid("invalid executable evidence spans")
	}
	result := make([]any, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		var span map[string]any
		if raw, ok := stringValue(item); ok {
			parts := strings.Split(raw, "-")
			if len(parts) != 2 {
				return nil, invalid("invalid line span")
			}
			start, e1 := strconv.Atoi(parts[0])
			end, e2 := strconv.Atoi(parts[1])
			if e1 != nil || e2 != nil || start <= 0 || end < start || end > 10_000_000 {
				return nil, invalid("invalid line span")
			}
			span = map[string]any{"startLine": start, "endLine": end}
		} else {
			obj, ok := object(item)
			if !ok || !exactKeys(obj, "startLine", "endLine", "textDigest") {
				return nil, invalid("invalid evidence span")
			}
			start, a := integer(obj["startLine"])
			end, b := integer(obj["endLine"])
			digest, c := stringValue(obj["textDigest"])
			if !a || !b || !c || start <= 0 || end < start || end > 10_000_000 || !digestRE.MatchString(digest) {
				return nil, invalid("invalid evidence span")
			}
			span = map[string]any{"startLine": start, "endLine": end, "textDigest": digest}
		}
		key := canonicalString(span)
		if seen[key] {
			return nil, invalid("duplicate evidence span")
		}
		seen[key] = true
		result = append(result, span)
	}
	sort.Slice(result, func(i, j int) bool { return canonicalString(result[i]) < canonicalString(result[j]) })
	return result, nil
}

func sourceRecord(raw any, project string) (map[string]any, error) {
	obj, ok := object(raw)
	if !ok {
		return nil, invalid("invalid evidence source")
	}
	allowed := map[string]bool{"id": true, "sourceId": true, "url": true, "revision": true, "immutableCommit": true, "contentDigest": true, "startLine": true, "endLine": true, "spans": true}
	for k := range obj {
		if !allowed[k] {
			return nil, invalid("unexpected evidence source field")
		}
	}
	id, hasID := stringValue(obj["id"])
	sourceID, hasSourceID := stringValue(obj["sourceId"])
	if hasID == hasSourceID {
		return nil, invalid("ambiguous evidence identity")
	}
	revision, hasRevision := stringValue(obj["revision"])
	immutable, hasImmutable := stringValue(obj["immutableCommit"])
	if hasSourceID {
		if !hasImmutable || hasRevision {
			return nil, invalid("invalid Prometheus source identity")
		}
		id = sourceID
		revision = immutable
	} else if hasImmutable {
		return nil, invalid("invalid generic source identity")
	}
	digest, ok := stringValue(obj["contentDigest"])
	if !idRE.MatchString(id) || !ok || !digestRE.MatchString(digest) {
		return nil, invalid("invalid source identity or digest")
	}
	rawURL, commit, err := immutableURL(obj["url"])
	if err != nil {
		return nil, err
	}
	result := map[string]any{"id": id, "url": rawURL, "contentDigest": digest, "projectID": project}
	if hasRevision || hasImmutable {
		if !commitRE.MatchString(revision) || revision != commit {
			return nil, invalid("invalid evidence revision")
		}
		result["revision"] = revision
	}
	_, hasStart := obj["startLine"]
	_, hasEnd := obj["endLine"]
	if hasStart || hasEnd {
		start, a := integer(obj["startLine"])
		end, b := integer(obj["endLine"])
		if !a || !b || start <= 0 || end < start || end > 10_000_000 {
			return nil, invalid("invalid source range")
		}
		result["startLine"] = start
		result["endLine"] = end
	}
	if spans, exists := obj["spans"]; exists {
		normalized, err := sourceSpans(spans)
		if err != nil {
			return nil, err
		}
		result["spans"] = normalized
	}
	return result, nil
}

func selectedRecords(document map[string]any) ([]map[string]any, map[string]any, error) {
	if !exactKeys(document, "schema", "provenance", "records") || document["schema"] != selectedSchema {
		return nil, nil, invalid("invalid selected-source schema")
	}
	provenance, ok := object(document["provenance"])
	if !ok || !exactKeys(provenance, "collectionIndexDigest", "referenceState", "licenseState") {
		return nil, nil, invalid("invalid selected-source provenance")
	}
	digest, _ := stringValue(provenance["collectionIndexDigest"])
	if !digestRE.MatchString(digest) || provenance["referenceState"] != "reference_only" || provenance["licenseState"] != "license_unreviewed" {
		return nil, nil, invalid("invalid selected-source provenance")
	}
	items, ok := array(document["records"])
	if !ok || len(items) == 0 {
		return nil, nil, invalid("selected-source records required")
	}
	seen := map[string]bool{}
	result := make([]map[string]any, 0, len(items))
	keys := []string{"id", "projectID", "canonicalRepositoryURL", "repositoryURL", "immutableURL", "commit", "version", "sourceKind", "contentDigest", "byteLength", "spans"}
	for _, raw := range items {
		record, ok := object(raw)
		if !ok || !exactKeys(record, keys...) {
			return nil, nil, invalid("unexpected selected-source record field")
		}
		id, _ := stringValue(record["id"])
		project, _ := stringValue(record["projectID"])
		commit, _ := stringValue(record["commit"])
		version, _ := validText(record["version"], 128)
		kind, _ := stringValue(record["sourceKind"])
		content, _ := stringValue(record["contentDigest"])
		length, lenOK := integer(record["byteLength"])
		if !idRE.MatchString(id) || seen[id] || !projectRE.MatchString(project) || len(project) > 80 || !commitRE.MatchString(commit) || version == "" || !sourceKinds[kind] || !digestRE.MatchString(content) || !lenOK || length <= 0 || length > 1<<20 {
			return nil, nil, invalid("invalid selected-source record")
		}
		canonical, err := httpsURL(record["canonicalRepositoryURL"], true)
		if err != nil {
			return nil, nil, err
		}
		repository, err := httpsURL(record["repositoryURL"], true)
		if err != nil {
			return nil, nil, err
		}
		immutable, immutableCommit, err := immutableURL(record["immutableURL"])
		if err != nil || immutableCommit != commit {
			return nil, nil, invalid("invalid selected immutable source")
		}
		spanItems, ok := array(record["spans"])
		if !ok || len(spanItems) == 0 {
			return nil, nil, invalid("selected-source spans required")
		}
		spans := make([]any, 0, len(spanItems))
		spanSeen := map[string]bool{}
		for _, item := range spanItems {
			span, ok := object(item)
			if !ok || !exactKeys(span, "startLine", "endLine", "spanDigest") {
				return nil, nil, invalid("invalid selected span")
			}
			start, a := integer(span["startLine"])
			end, b := integer(span["endLine"])
			d, c := stringValue(span["spanDigest"])
			if !a || !b || !c || start <= 0 || end < start || end > 10_000_000 || !digestRE.MatchString(d) {
				return nil, nil, invalid("invalid selected span bounds")
			}
			normalized := map[string]any{"startLine": start, "endLine": end, "spanDigest": d}
			key := canonicalString(normalized)
			if spanSeen[key] {
				return nil, nil, invalid("duplicate selected span")
			}
			spanSeen[key] = true
			spans = append(spans, normalized)
		}
		sort.Slice(spans, func(i, j int) bool {
			a := spans[i].(map[string]any)
			b := spans[j].(map[string]any)
			if a["startLine"].(int) != b["startLine"].(int) {
				return a["startLine"].(int) < b["startLine"].(int)
			}
			if a["endLine"].(int) != b["endLine"].(int) {
				return a["endLine"].(int) < b["endLine"].(int)
			}
			return a["spanDigest"].(string) < b["spanDigest"].(string)
		})
		seen[id] = true
		result = append(result, map[string]any{"id": id, "projectID": project, "canonicalRepositoryURL": canonical, "repositoryURL": repository, "immutableURL": immutable, "commit": commit, "version": version, "sourceKind": kind, "contentDigest": content, "byteLength": length, "spans": spans, "referenceState": "reference_only", "licenseState": "license_unreviewed"})
	}
	sort.Slice(result, func(i, j int) bool { return result[i]["id"].(string) < result[j]["id"].(string) })
	return result, map[string]any{"collectionIndexDigest": digest, "referenceState": "reference_only", "licenseState": "license_unreviewed"}, nil
}

func (cfg Config) loadPreparerSource(path string) ([]byte, string, error) {
	raw, err := cfg.readInput(path, maxCNCFPrepareSourceBytes)
	if err != nil {
		return nil, "", fmt.Errorf("read CNCF preparer dispatch: %w", err)
	}
	if len(raw) > maxCNCFPrepareSourceBytes {
		return nil, "", invalid("CNCF preparer dispatch exceeds the bounded size")
	}
	return raw, fmt.Sprintf("sha256:%x", sha256.Sum256(raw)), nil
}

func preparerProjects(source []byte) (map[string]bool, error) {
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, "cncf_prepare.go", source, 0)
	if err != nil {
		return nil, invalid("CNCF preparer dispatch cannot be parsed")
	}
	result := map[string]bool{}
	ast.Inspect(parsed, func(node ast.Node) bool {
		switchStmt, ok := node.(*ast.SwitchStmt)
		if !ok || !projectSwitch(switchStmt.Tag) {
			return true
		}
		for _, item := range switchStmt.Body.List {
			clause, ok := item.(*ast.CaseClause)
			if !ok || !casePrepares(clause) {
				continue
			}
			for _, value := range clause.List {
				literal, ok := value.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					continue
				}
				project, err := strconv.Unquote(literal.Value)
				if err == nil && projectRE.MatchString(project) {
					result[project] = true
				}
			}
		}
		return true
	})
	if len(result) == 0 {
		return nil, invalid("CNCF preparer dispatch block missing")
	}
	return result, nil
}

func projectSwitch(value ast.Expr) bool {
	star, ok := value.(*ast.StarExpr)
	if !ok {
		return false
	}
	name, ok := star.X.(*ast.Ident)
	return ok && name.Name == "project"
}

func casePrepares(clause *ast.CaseClause) bool {
	found := false
	for _, statement := range clause.Body {
		ast.Inspect(statement, func(node ast.Node) bool {
			assign, ok := node.(*ast.AssignStmt)
			if !ok || len(assign.Lhs) == 0 {
				return true
			}
			name, ok := assign.Lhs[0].(*ast.Ident)
			if !ok || name.Name != "prepared" {
				return true
			}
			for _, rhs := range assign.Rhs {
				if call, ok := rhs.(*ast.CallExpr); ok && cncfPrepareCall(call) {
					found = true
				}
			}
			return true
		})
	}
	return found
}

func cncfPrepareCall(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || !strings.HasPrefix(selector.Sel.Name, "Prepare") {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	return ok && pkg.Name == "cncfprepare"
}

func transition(rule map[string]any) (map[string]any, error) {
	subject, ok := object(rule["subject"])
	if !ok {
		return nil, invalid("missing rule subject")
	}
	component, err := validText(subject["component"], 240)
	from, a := stringValue(subject["from"])
	to, b := stringValue(subject["to"])
	if err != nil || !a || !b || !versionRE.MatchString(from) || !versionRE.MatchString(to) {
		return nil, invalid("invalid rule transition")
	}
	result := map[string]any{"component": component, "from": from, "to": to, "semantics": "exact_declared_endpoints_only"}
	if rawRange, ranged := rule["range"]; ranged {
		// A reviewed range is recorded as the rule declares it; the anchor
		// endpoints stay the reviewed identity. The engine enforces the range
		// guards; this inventory only reports the declared bounds.
		value, ok := object(rawRange)
		fromBound, fromOK := object(value["from"])
		toBound, toOK := object(value["to"])
		if !ok || !fromOK || !toOK {
			return nil, invalid("invalid rule range")
		}
		bounds := map[string]any{}
		for name, bound := range map[string]map[string]any{"from": fromBound, "to": toBound} {
			gte, gteOK := stringValue(bound["gte"])
			lt, ltOK := stringValue(bound["lt"])
			if !gteOK || !ltOK || !versionRE.MatchString(gte) || !versionRE.MatchString(lt) {
				return nil, invalid("invalid rule range bound")
			}
			bounds[name] = map[string]any{"gte": gte, "lt": lt}
		}
		result["semantics"] = "exact_anchor_endpoints_and_reviewed_half_open_range"
		result["range"] = bounds
	}
	return result, nil
}

// packSchemaMatchesRanges accepts the ranged pack schema exactly when at least
// one rule declares a range, mirroring the embedded pack loaders.
func packSchemaMatchesRanges(rules map[string]any, exactSchema, rangedSchema string) bool {
	entries, _ := array(rules["entries"])
	ranged := false
	for _, item := range entries {
		entry, _ := object(item)
		rule, _ := object(entry["rule"])
		if _, ok := rule["range"]; ok {
			ranged = true
		}
	}
	if ranged {
		return rules["schema"] == rangedSchema
	}
	return rules["schema"] == exactSchema
}

// genericProjects reads the embedded CNCF source-rule pack. A rule whose
// evidence is withdrawn contributes no executable capability (its claim is
// always UNKNOWN, so it establishes no support): it is excluded from the
// returned projects and from ruleCount, but is still reported by the
// withdrawn return value so the generated inventory can say explicitly why
// coverage shrank, rather than silently dropping it.
func genericProjects(rules map[string]any, identities map[string]identity, preparers map[string]bool) ([]map[string]any, int, []map[string]any, error) {
	if !packSchemaMatchesRanges(rules, "prufyx.io/cncf-source-rule-pack/v1alpha1", "prufyx.io/cncf-source-rule-pack/v1alpha2") {
		return nil, 0, nil, invalid("invalid rule-pack schema")
	}
	entries, ok := array(rules["entries"])
	if !ok || len(entries) == 0 {
		return nil, 0, nil, invalid("missing rule entries")
	}
	grouped := map[string][]any{}
	seen := map[string]bool{}
	var withdrawn []map[string]any
	ruleCount := 0
	for _, item := range entries {
		entry, ok := object(item)
		if !ok {
			return nil, 0, nil, invalid("invalid rule entry")
		}
		project, _ := stringValue(entry["project"])
		if _, ok := identities[project]; !ok {
			return nil, 0, nil, invalid("rule project absent from landscape")
		}
		rule, ok := object(entry["rule"])
		if !ok {
			return nil, 0, nil, invalid("invalid rule")
		}
		id, _ := stringValue(rule["id"])
		if !idRE.MatchString(id) || seen[id] {
			return nil, 0, nil, invalid("duplicate rule")
		}
		seen[id] = true
		evidence, ok := object(rule["evidence"])
		if !ok || (evidence["state"] != "active" && evidence["state"] != "withdrawn") {
			return nil, 0, nil, invalid("inactive evidence")
		}
		if evidence["state"] == "withdrawn" {
			withdrawn = append(withdrawn, map[string]any{"ruleID": id, "project": project, "family": "cncf_embedded_source_rule", "reasonCode": "RULE_EVIDENCE_WITHDRAWN"})
			continue
		}
		sources, ok := array(evidence["sources"])
		if !ok || len(sources) == 0 {
			return nil, 0, nil, invalid("missing evidence")
		}
		normalized := make([]any, 0, len(sources))
		for _, source := range sources {
			v, err := sourceRecord(source, project)
			if err != nil {
				return nil, 0, nil, err
			}
			normalized = append(normalized, v)
		}
		tr, err := transition(rule)
		if err != nil {
			return nil, 0, nil, err
		}
		grouped[project] = append(grouped[project], map[string]any{"ruleID": id, "transition": tr, "evidence": normalized, "evidenceState": "active", "limit": "Scoped operator-declared constraint; a PASS, BLOCKED, or UNKNOWN claim never proves whole-upgrade safety or runtime behavior."})
		ruleCount++
	}
	names := make([]string, 0, len(grouped))
	for name := range grouped {
		names = append(names, name)
	}
	sort.Strings(names)
	projects := make([]map[string]any, 0, len(names))
	for _, project := range names {
		id := identities[project]
		if id.repository == "" {
			return nil, 0, nil, invalid("executable project lacks repository")
		}
		if _, err := httpsURL(id.repository, true); err != nil {
			return nil, 0, nil, err
		}
		sort.Slice(grouped[project], func(i, j int) bool {
			return grouped[project][i].(map[string]any)["ruleID"].(string) < grouped[project][j].(map[string]any)["ruleID"].(string)
		})
		capability := map[string]any{"kind": "embedded_cncf_source_rule", "command": []any{"check", "cncf", "--project", project}, "rules": grouped[project], "metadataState": "embedded_active_source_rule_pack"}
		if project == "argo-cd" {
			// Preserve the published generic preparer for v1 readers. The plural
			// routes distinguish its selected RBAC ConfigMap check from the
			// separately scoped resource-exclusions check.
			legacy := map[string]any{"command": []any{"prepare", "cncf", "--project", "argo-cd"}, "metadataState": "implemented_local_minimizing_adapter", "limit": "The adapter prepares only a bounded operator declaration from one local private input; it does not inspect a cluster, run an upgrade, or establish runtime behavior."}
			capability["localPreparer"] = legacy
			capability["localPreparers"] = []any{
				legacy,
				map[string]any{
					"command":       []any{"check", "cncf", "--project", "argo-cd", "--config-map", "FILE", "--from", "2.14.0", "--to", "3.0.0"},
					"metadataState": "implemented_native_selected_argocd_rbac_config_map_minimizer",
					"limit":         "Checks one caller-selected native Argo CD argocd-cm JSON for the selected inheritance setting and explicit RBAC intent. It evaluates only that selected rule; other project rules, ConfigMap keys, RBAC grants, resource existence, watches, UI, reconciliation, runtime behavior, and whole-upgrade safety remain UNKNOWN.",
				},
				map[string]any{
					"command":       []any{"check", "cncf", "--project", "argo-cd", "--resource-exclusions-config-map", "FILE", "--from", "2.14.0", "--to", "3.0.0", "--resource-exclusions-config-complete", "--resource-exclusions-precedence-resolved", "--requires-v2-visibility-of-v3-default-excluded-resources", "true"},
					"metadataState": "implemented_native_selected_argocd_resource_exclusions_minimizer",
					"limit":         "Checks one caller-selected complete, precedence-resolved native Argo CD argocd-cm YAML for an absent, explicit empty, or exact reviewed resource.exclusions target default with explicit v2-visibility-preservation intent. Other values, resource existence, watches, UI, reconciliation, runtime behavior, and whole-upgrade safety remain UNKNOWN.",
				},
			}
		} else if native, ok := nativeCNCFRoutes(project); ok {
			if len(native) == 1 {
				capability["localPreparer"] = native[0].inventoryValue()
			} else {
				// Preserve the established scrape route for v1 readers. New readers
				// use localPreparers to discover every independently scoped route.
				legacy := native[0]
				for _, route := range native {
					if route["metadataState"] == "implemented_native_selected_scrape_config_minimizer" {
						legacy = route
						break
					}
				}
				capability["localPreparer"] = legacy.inventoryValue()
				routes := make([]any, 0, len(native))
				for _, route := range native {
					routes = append(routes, route.inventoryValue())
				}
				capability["localPreparers"] = routes
			}
		} else if preparers[project] {
			capability["localPreparer"] = map[string]any{"command": []any{"prepare", "cncf", "--project", project}, "metadataState": "implemented_local_minimizing_adapter", "limit": "The adapter prepares only a bounded operator declaration from one local private input; it does not inspect a cluster, run an upgrade, or establish runtime behavior."}
		}
		projects = append(projects, map[string]any{"projectID": project, "displayName": id.name, "repositoryURL": id.repository, "supportState": "executable", "capabilities": []any{capability}, "selectedSourceRecords": []any{}})
	}
	sort.Slice(withdrawn, func(i, j int) bool { return withdrawn[i]["ruleID"].(string) < withdrawn[j]["ruleID"].(string) })
	return projects, ruleCount, withdrawn, nil
}

func nativeCNCFRoutes(project string) ([]nativeCNCFInputRoute, bool) {
	if legacy, ok := checkroutemetadata.LegacyInventoryRoutes(project); ok {
		routes := make([]nativeCNCFInputRoute, 0, len(legacy))
		for _, route := range legacy {
			routes = append(routes, nativeCNCFInputRoute{"command": route.Command, "metadataState": route.MetadataState, "limit": route.Limit})
		}
		return routes, true
	}
	routes, ok := nativeCNCFInputMetadata[project]
	return routes, ok
}

// nativeCNCFInputMetadata describes direct check routes that intentionally do
// not use the generic prepare command. Each route minimizes one caller-supplied
// local input in memory; none inspects a cluster or proves runtime behavior.
type nativeCNCFInputRoute map[string]any

func (route nativeCNCFInputRoute) inventoryValue() map[string]any {
	return map[string]any(route)
}

var nativeCNCFInputMetadata = map[string][]nativeCNCFInputRoute{
	"containerd": {
		{
			"command":       []any{"prepare", "cncf", "--project", "containerd", "--input", "FILE", "--runtime-handler", "NAME", "--containerd-config-complete", "--containerd-config-precedence-resolved", "--containerd-official-upstream", "--containerd-official-bundled-runtimes-only"},
			"metadataState": "implemented_native_selected_containerd_config_preparer",
			"limit":         "Prepares only the selected CRI runtime_type predicate from one caller-supplied native containerd config version 2 or 3. Version-pair coverage is selected by the rule pack. Imports, runtime_path overrides, custom runtimes, missing handlers, host shim availability, runtime behavior, and whole-upgrade safety remain UNKNOWN.",
		},
		{
			"command":       []any{"check", "cncf", "--project", "containerd", "--containerd-config", "FILE", "--runtime-handler", "NAME", "--from", "1.7.28", "--to", "2.0.0", "--containerd-config-complete", "--containerd-config-precedence-resolved", "--containerd-official-upstream", "--containerd-official-bundled-runtimes-only"},
			"metadataState": "implemented_native_selected_containerd_config_minimizer",
			"limit":         "Checks only whether one explicitly selected CRI handler uses an official bundled runtime shim removed in 2.0. Config version 2 is admitted through the reviewed target migration. Caller declarations bind completeness, precedence, upstream distribution, and absence of a separately installed custom shim; startup, container creation, runtime behavior, and whole-upgrade safety remain UNKNOWN.",
		},
	},
	"thanos": {{
		"command":       []any{"check", "cncf", "--project", "thanos", "--native-resource", "FILE"},
		"metadataState": "implemented_native_kubernetes_workload_minimizer",
		"limit":         "Checks one selected Thanos Receive or Store container in a caller-supplied Kubernetes workload with an exact reviewed image and literal argv; unresolved entrypoints, arguments, images, runtime behavior, storage, Query behavior, and whole-upgrade safety remain UNKNOWN.",
	}},
	"cortex": {{
		"command":       []any{"check", "cncf", "--project", "cortex", "--native-resource", "FILE"},
		"metadataState": "implemented_native_kubernetes_workload_minimizer",
		"limit":         "Checks one selected Cortex container in a caller-supplied Kubernetes workload with the exact reviewed image and literal argv. Explicit /bin/cortex is admitted; an omitted command is source-derived only for the exact admitted target image, never runtime observation. Null, empty, wrapper, custom-image, or unresolved entrypoints and arguments remain UNKNOWN; query semantics, runtime behavior, and whole-upgrade safety remain UNKNOWN.",
	}},
	"nats": {{
		"command":       []any{"check", "cncf", "--project", "nats", "--nats-config", "FILE"},
		"metadataState": "implemented_native_json_configuration_minimizer",
		"limit":         "Checks only supplied literal server_name, cluster.name, and gateway.name in a bounded native JSON configuration subset; includes, variables, defaults, startup behavior, connectivity, and whole-upgrade safety remain UNKNOWN.",
	}},
	"flux": {{
		"command":       []any{"check", "cncf", "--project", "flux", "--native-resource", "FILE"},
		"metadataState": "implemented_native_rendered_resource_minimizer",
		"limit":         "Checks one caller-selected JSON Kubernetes resource or v1 List for the historical five beta API versions and the additive Flux 2.9.5 beta2 union; latest coverage is limited to the reviewed toolkit kinds and five exact origins, while source-watcher, extensions, and unreviewed API versions remain UNKNOWN. Absence requires an explicit complete non-paginated selected set, and stored versions, cluster inventory, reconciliation, runtime behavior, and whole-upgrade safety remain UNKNOWN.",
	}},
	"kubernetes": {{
		"command":       []any{"check", "cncf", "--project", "kubernetes", "--native-resource", "FILE", "--from", "1.31.0", "--to", "1.32.0", "--distribution", "official_upstream", "--target-api-apply-required", "--resource-scope-complete"},
		"metadataState": "implemented_native_rendered_resource_minimizer",
		"limit":         "Checks one caller-selected complete non-paginated rendered target apply set for FlowSchema and PriorityLevelConfiguration at flowcontrol.apiserver.k8s.io/v1beta3 under caller-declared official-upstream distribution and target API apply intent. General manifest admission, CRDs, stored objects, runtime clients, API-server configuration, and whole-upgrade safety remain UNKNOWN.",
	}},
	"cilium": {{
		"command":       []any{"check", "cncf", "--project", "cilium", "--cilium-config-map", "FILE", "--from", "1.16.19", "--to", "1.17.18", "--cilium-distribution", "official_upstream", "--cilium-config-complete", "--cilium-config-precedence-resolved"},
		"metadataState": "implemented_native_selected_configmap_minimizer",
		"limit":         "Checks only the whitespace-trimmed literal cluster-name in one caller-selected complete, precedence-resolved official-upstream v1 ConfigMap for the exact Cilium 1.16.19 to 1.17.18 transition. ClusterMesh, networking, name collisions, source configuration discovery, runtime behavior, and whole-upgrade safety remain UNKNOWN.",
	}},
	"coredns": {{
		"command":       []any{"check", "cncf", "--project", "coredns", "--coredns-corefile", "FILE", "--coredns-corefile-complete", "--coredns-distribution", "official", "--from", "1.13.2", "--to", "1.14.7"},
		"metadataState": "implemented_native_selected_coredns_corefile_minimizer",
		"limit":         "Checks only direct federation directive presence in one caller-selected complete Corefile under a caller-declared official distribution. The route is limited to the reviewed 1.6.9 to 1.7.0 transition and origins 1.9.4, 1.10.1, 1.11.4, 1.12.4, or 1.13.2 to target 1.14.7. Imports, snippets, substitutions, custom distributions, unsupported structure, plugin validity, DNS behavior, runtime state, and whole-upgrade safety remain UNKNOWN.",
	}},
	"opentelemetry": {
		{
			"command":       []any{"check", "cncf", "--project", "opentelemetry", "--otel-collector-config", "FILE", "--otel-distribution", "official|custom", "--otel-config-complete", "--otel-config-precedence-resolved", "--from", "0.110.0", "--to", "0.111.0"},
			"metadataState": "implemented_native_selected_opentelemetry_collector_config_minimizer",
			"limit":         "Checks one caller-selected complete, precedence-resolved native OpenTelemetry Collector configuration for a logging exporter under a caller-declared official distribution. Unsupported YAML or values, defaults, custom distributions, resource presence, pipeline behavior, exporter execution, runtime behavior, and whole-upgrade safety remain UNKNOWN.",
		},
		{
			"command":       []any{"check", "cncf", "--project", "opentelemetry", "--otel-rule", "internal-telemetry-default-bind", "--otel-collector-config", "FILE", "--otel-distribution", "official", "--otel-config-complete", "--otel-config-precedence-resolved", "--otel-metrics-localhost-default", "true|false", "--otel-metrics-remote-scrape-required", "true|false", "--from", "0.110.0", "--to", "0.111.0"},
			"metadataState": "implemented_native_selected_opentelemetry_internal_metrics_minimizer",
			"limit":         "Checks only the source-defined internal-metrics default bind for one caller-selected complete, precedence-resolved official Collector configuration without a service.telemetry.metrics override. The feature gate and remote-scrape requirement are caller declarations; missing authority, unsupported syntax or distribution, listener or scrape behavior, runtime behavior, and whole-upgrade safety remain UNKNOWN.",
		},
	},
}

func communityProjects(rules, registry map[string]any) ([]map[string]any, int, error) {
	if !packSchemaMatchesRanges(rules, "prufyx.io/community-project-source-rule-pack/v1alpha1", "prufyx.io/community-project-source-rule-pack/v1alpha2") || registry["schema"] != "prufyx.io/community-project-registry/v1alpha1" {
		return nil, 0, invalid("invalid community-project source schema")
	}
	rawIdentities, ok := array(registry["projects"])
	if !ok || len(rawIdentities) == 0 {
		return nil, 0, invalid("missing community-project registry")
	}
	identities := map[string]identity{}
	components := map[string]string{}
	for _, raw := range rawIdentities {
		item, ok := object(raw)
		if !ok || item["identityAuthority"] != "MAINTAINER_REVIEWED_EXTERNAL_REPOSITORY" || item["cncfMembership"] != "NOT_ASSERTED" {
			return nil, 0, invalid("invalid community-project identity authority")
		}
		slug, _ := stringValue(item["slug"])
		name, err := validText(item["name"], 240)
		repository, _ := stringValue(item["repositoryURL"])
		component, componentErr := validText(item["component"], 240)
		if err != nil || componentErr != nil || !projectRE.MatchString(slug) || identities[slug].name != "" || repository == "" {
			return nil, 0, invalid("invalid community-project identity")
		}
		if _, err := httpsURL(repository, true); err != nil {
			return nil, 0, err
		}
		identities[slug], components[slug] = identity{name, repository}, component
	}
	entries, ok := array(rules["entries"])
	if !ok || len(entries) == 0 {
		return nil, 0, invalid("missing community-project rules")
	}
	grouped := map[string][]any{}
	seen := map[string]bool{}
	for _, raw := range entries {
		entry, ok := object(raw)
		if !ok {
			return nil, 0, invalid("invalid community-project rule entry")
		}
		project, _ := stringValue(entry["project"])
		if identities[project].name == "" {
			return nil, 0, invalid("community-project rule identity missing")
		}
		rule, ok := object(entry["rule"])
		if !ok {
			return nil, 0, invalid("invalid community-project rule")
		}
		id, _ := stringValue(rule["id"])
		if !idRE.MatchString(id) || seen[id] {
			return nil, 0, invalid("duplicate community-project rule")
		}
		seen[id] = true
		tr, err := transition(rule)
		if err != nil || tr["component"] != components[project] {
			return nil, 0, invalid("community-project transition identity mismatch")
		}
		evidence, ok := object(rule["evidence"])
		if !ok || evidence["state"] != "active" {
			return nil, 0, invalid("inactive community-project evidence")
		}
		sources, ok := array(evidence["sources"])
		if !ok || len(sources) == 0 {
			return nil, 0, invalid("missing community-project evidence")
		}
		normalized := make([]any, 0, len(sources))
		for _, source := range sources {
			v, err := sourceRecord(source, project)
			if err != nil {
				return nil, 0, err
			}
			normalized = append(normalized, v)
		}
		limit := "Scoped native effective-configuration constraint; it does not assert CNCF membership, whole-upgrade safety, or runtime behavior."
		if project == "argo-workflows" {
			limit = "Scoped literal argv constraint for one selected native Kubernetes workload container; it does not assert CNCF membership, whole-upgrade safety, or runtime behavior."
		} else if project == "ceph" {
			limit = "Scoped current-backend constraint for one explicitly selected caller-supplied OSD metadata object; it does not assert other OSDs, cluster inventory, target deployment, whole-upgrade safety, or runtime behavior."
		} else if project == "mariadb" {
			limit = "Scoped explicit requirement for removed upstream MariaDB InnoDB defragmentation behavior; option presence alone does not assert startup failure, packaged or fork behavior, whole-upgrade safety, or runtime behavior."
		} else if project == "mariadb-operator" {
			limit = "Scoped Galera-only prerequisite for one complete caller-selected MariaDB resource before the 26.3.0 to 26.6.0 operator update; it does not inspect admission, cluster state, runtime behavior, controller progress, data-plane completion, or whole-upgrade safety."
		}
		grouped[project] = append(grouped[project], map[string]any{"ruleID": id, "transition": tr, "evidence": normalized, "evidenceState": "active", "limit": limit})
	}
	names := make([]string, 0, len(grouped))
	for name := range grouped {
		names = append(names, name)
	}
	sort.Strings(names)
	projects := make([]map[string]any, 0, len(names))
	for _, project := range names {
		sort.Slice(grouped[project], func(i, j int) bool {
			return grouped[project][i].(map[string]any)["ruleID"].(string) < grouped[project][j].(map[string]any)["ruleID"].(string)
		})
		preparer := map[string]any{"command": []any{"prepare", "project", "--project", project}, "metadataState": "implemented_native_effective_config_minimizer", "limit": "Requires caller-declared complete configuration with environment and CLI precedence resolved; unsupported syntax remains UNKNOWN."}
		if project == "argo-workflows" {
			preparer = map[string]any{"command": []any{"prepare", "project", "--project", project}, "metadataState": "implemented_native_kubernetes_workload_minimizer", "limit": "Requires a caller-declared complete selected-container argv, exact reviewed image, and explicit command or the reviewed exact-image ENTRYPOINT default; unsupported context remains UNKNOWN."}
		} else if project == "ceph" {
			preparer = map[string]any{"command": []any{"prepare", "project", "--project", project}, "metadataState": "implemented_native_selected_current_osd_metadata_minimizer", "limit": "Requires one caller-selected current OSD metadata object, an exact matching numeric OSD id, and explicit object completeness; it does not inspect a cluster or target deployment."}
		} else if project == "fluent-bit" {
			preparer = map[string]any{"command": []any{"prepare", "project", "--project", project, "--effective-config", "FILE", "--from", "3.2.0", "--to", "4.0.0", "--effective-config-complete", "--current-default-was-used", "--preserve-http2-enabled"}, "metadataState": "implemented_native_classic_configuration_minimizer", "limit": "Requires one caller-selected complete classic [OUTPUT] configuration and caller declarations that the current default was used and HTTP/2 must remain enabled; it evaluates only that setting. Unsupported syntax remains UNKNOWN."}
		} else if project == "mariadb" {
			preparer = map[string]any{"command": []any{"prepare", "project", "--project", project, "--effective-config", "FILE", "--from", "10.11.8", "--to", "11.4.2", "--effective-config-complete", "--precedence-resolved", "--upstream-distribution", "--require-innodb-defragmentation", "true|false"}, "metadataState": "implemented_native_mariadb_option_file_minimizer", "limit": "Requires one caller-selected complete, precedence-resolved upstream MariaDB option file and an explicit true or false removed-behavior requirement. Includes, aliases, prefixes, unsupported groups, packaged or fork-specific behavior remain UNKNOWN."}
		} else if project == "mariadb-operator" {
			route, ok := checkroutemetadata.LegacyCommunityInventoryRoute(project)
			if !ok {
				return nil, 0, invalid("missing MariaDB Operator legacy route")
			}
			preparer = map[string]any{"command": route.Command, "metadataState": route.MetadataState, "limit": route.Limit}
		}
		capability := map[string]any{"kind": "embedded_community_project_source_rule", "command": []any{"check", "project", "--project", project}, "rules": grouped[project], "metadataState": "embedded_active_source_rule_pack_no_external_update", "localPreparer": preparer}
		if project == "loki" {
			// Keep the established generic compactor preparer for v1 readers while
			// exposing both independently selected native Loki routes to v2 readers.
			capability["localPreparers"] = []any{
				preparer,
				map[string]any{
					"command":       []any{"check", "project", "--project", "loki", "--loki-schema-config", "FILE", "--from", "2.9.8", "--to", "3.0.0", "--effective-config-complete", "--precedence-resolved"},
					"metadataState": "implemented_native_selected_loki_schema_config_minimizer",
					"limit":         "Checks one caller-selected complete, precedence-resolved native Loki schema configuration: one canonical period with literal store and schema plus explicit allow_structured_metadata. An omitted allow setting requires exact-pair --use-reviewed-target-default. Multiple periods, aliases, tags, duplicate or near-key spellings, templates, unsupported values, other precedence, storage migration, retention, data access, runtime behavior, and whole-upgrade safety remain UNKNOWN.",
				},
			}
		}
		id := identities[project]
		projects = append(projects, map[string]any{"projectID": project, "displayName": id.name, "repositoryURL": id.repository, "supportState": "executable", "capabilities": []any{capability}, "selectedSourceRecords": []any{}})
	}
	return projects, len(entries), nil
}

func namedProject(contract map[string]any, digest string, identities map[string]identity, check string) (map[string]any, error) {
	var project, component, limit string
	var current, proposed map[string]any
	var sources []any
	var ok bool
	if check == "cert-manager-values" {
		if contract["schema"] != "prufyx.io/cert-manager-removed-monitor-values-source-contract/v1" {
			return nil, invalid("invalid cert contract")
		}
		project = "cert-manager"
		component, _ = stringValue(contract["component"])
		current, _ = object(contract["current"])
		proposed, _ = object(contract["target"])
		sources, ok = array(contract["sources"])
		limit = "Checks only three curated removed values paths; it does not validate the full target schema, runtime behavior, or whole-upgrade compatibility."
	} else {
		if contract["schema"] != "prufyx.io/prometheus-mode-source-contract/v1" {
			return nil, invalid("invalid Prometheus contract")
		}
		project = "prometheus"
		component, _ = stringValue(contract["componentId"])
		current, _ = object(contract["current"])
		proposed, _ = object(contract["proposed"])
		sources, ok = array(contract["sources"])
		limit, _ = stringValue(contract["claimLimit"])
	}
	id, exists := identities[project]
	from, _ := stringValue(current["version"])
	to, _ := stringValue(proposed["version"])
	if !exists || component == "" || !ok || len(sources) == 0 || !versionRE.MatchString(from) || !versionRE.MatchString(to) || limit == "" || id.repository == "" {
		return nil, invalid("invalid named check")
	}
	normalized := make([]any, 0, len(sources))
	for _, source := range sources {
		v, err := sourceRecord(source, project)
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, v)
	}
	transitions := []any{map[string]any{"component": component, "from": from, "to": to, "semantics": "exact_reviewed_transition_only"}}
	if check == "cert-manager-values" {
		if latest, ok := object(contract["_latestContract"]); ok {
			latestTransitions, _ := array(latest["transitions"])
			latestSources, _ := array(latest["sources"])
			seenEvidenceIDs := map[string]bool{}
			for _, item := range normalized {
				if evidence, ok := object(item); ok {
					if id, ok := stringValue(evidence["id"]); ok {
						seenEvidenceIDs[id] = true
					}
				}
			}
			for _, rawTransition := range latestTransitions {
				item, itemOK := object(rawTransition)
				old, oldOK := object(item["current"])
				new, newOK := object(item["target"])
				oldVersion, oldVersionOK := stringValue(old["version"])
				newVersion, newVersionOK := stringValue(new["version"])
				oldDigest, oldDigestOK := stringValue(old["chartManifestDigest"])
				newDigest, newDigestOK := stringValue(new["chartManifestDigest"])
				if !itemOK || !oldOK || !newOK || !oldVersionOK || !newVersionOK || !oldDigestOK || !newDigestOK || !digestRE.MatchString(oldDigest) || !digestRE.MatchString(newDigest) {
					return nil, invalid("invalid latest cert transition")
				}
				transitions = append(transitions, map[string]any{"component": component, "from": oldVersion, "to": newVersion, "currentChartManifestDigest": oldDigest, "targetChartManifestDigest": newDigest, "semantics": "exact_reviewed_transition_only"})
			}
			for _, rawSource := range latestSources {
				// The inventory evidence schema is intentionally GitHub-only. The
				// chart OCI digest remains bound in the executable contract and
				// transitions; the immutable GitHub-backed schema and guide evidence
				// is rendered here.
				item, itemOK := object(rawSource)
				if !itemOK || item["id"] == "oci-manifest-target" {
					continue
				}
				id, idOK := stringValue(item["id"])
				if !idOK {
					return nil, invalid("invalid latest cert evidence identity")
				}
				if id == "target-values-schema" {
					// Keep the historical evidence identity and expose the latest
					// commit-pinned identity alongside it.
					id = "latest-target-values-schema"
					item["id"] = id
				}
				if seenEvidenceIDs[id] {
					continue
				}
				v, err := sourceRecord(item, project)
				if err != nil {
					return nil, err
				}
				normalized = append(normalized, v)
				seenEvidenceIDs[id] = true
			}
		}
	}
	capability := map[string]any{"kind": "named_local_check", "command": []any{"check", check}, "transitions": transitions, "evidence": normalized, "metadataState": "embedded_source_contract", "sourceContractDigest": digest, "limit": limit}
	if latest, ok := object(contract["_latestContract"]); ok {
		if latestDigest, ok := stringValue(contract["_latestDigest"]); ok {
			if check == "cert-manager-values" {
				capability["latestSourceContractDigest"] = latestDigest
				if target, ok := object(latest["target"]); ok {
					capability["latestTarget"] = target
				}
			}
		}
	}
	return map[string]any{"projectID": project, "displayName": id.name, "repositoryURL": id.repository, "supportState": "executable", "capabilities": []any{capability}, "selectedSourceRecords": []any{}}, nil
}

func spansFromNormative(raw any) ([]any, error) {
	items, ok := array(raw)
	if !ok || len(items) == 0 {
		return nil, invalid("invalid normative source spans")
	}
	result := make([]any, 0, len(items))
	for _, item := range items {
		span, ok := object(item)
		if !ok {
			return nil, invalid("invalid normative source span")
		}
		start, startOK := integer(span["startLine"])
		end, endOK := integer(span["endLine"])
		if !startOK || !endOK || start <= 0 || end < start || end > 10_000_000 {
			return nil, invalid("invalid normative source span bounds")
		}
		result = append(result, fmt.Sprintf("%d-%d", start, end))
	}
	return result, nil
}

func requireSingleRule(profile map[string]any, expected string) error {
	rules, ok := array(profile["rules"])
	if !ok || len(rules) != 1 {
		return invalid("invalid embedded profile rule count")
	}
	rule, ok := object(rules[0])
	if !ok || rule["id"] != expected {
		return invalid("invalid embedded profile rule")
	}
	return nil
}

func conformanceProject(profile map[string]any, digest string, identities map[string]identity, kind string) (map[string]any, error) {
	project := kind
	id, ok := identities[project]
	if !ok {
		return nil, invalid("conformance identity missing")
	}
	var command, profileID, limit string
	var evidence []any
	if kind == "spiffe" {
		if profile["apiVersion"] != "prufyx.io/spiffe-x509-svid-profile/v1" || profile["kind"] != "SPIFFEX509SVIDProfile" || profile["purpose"] != "standards_conformance" || profile["engineCapabilityDigest"] != "sha256:33c6a42388c6d1f340c97dc03179423a1d24d5c92292fea97414c61350f1abbf" || profile["revision"] != "1" {
			return nil, invalid("invalid SPIFFE profile")
		}
		if err := requireSingleRule(profile, "spiffe-x509-svid-public-leaf-uri-san-v1"); err != nil {
			return nil, invalid("invalid SPIFFE rule")
		}
		source, _ := object(profile["normativeSource"])
		repository, _ := stringValue(source["repositoryURL"])
		sourcePath, _ := stringValue(source["path"])
		commit, _ := stringValue(source["commit"])
		content, _ := stringValue(source["contentDigest"])
		if repository != "https://github.com/spiffe/spiffe" || sourcePath != "standards/X509-SVID.md" || id.repository != repository {
			return nil, invalid("SPIFFE source mismatch")
		}
		spans, err := spansFromNormative(source["spans"])
		if err != nil {
			return nil, err
		}
		v, err := sourceRecord(map[string]any{"id": "spiffe-x509-svid-public-leaf-profile", "url": repository + "/blob/" + commit + "/" + sourcePath, "revision": commit, "contentDigest": content, "spans": spans}, project)
		if err != nil {
			return nil, err
		}
		evidence = []any{v}
		command = "spiffe-x509-svid"
		profileID = "public-non-ca-leaf-single-spiffe-uri-non-root-path-v1"
		limit = "Checks one named URI-SAN subset only; it does not validate a complete SPIFFE ID, X.509-SVID, trust chain, possession, authentication, issuance, or runtime use."
	} else {
		if profile["apiVersion"] != "prufyx.io/cloudevents-structured-json-profile/v1" || profile["kind"] != "CloudEventsStructuredJSONProfile" || profile["purpose"] != "standards_conformance" || profile["engineCapabilityDigest"] != "sha256:94cc3006e46ce20a4c2579eb4d1eb99dfaee9fe00a4396ec3f4ee5ed204313bb" || profile["revision"] != "1" {
			return nil, invalid("invalid CloudEvents profile")
		}
		if err := requireSingleRule(profile, "cloudevents-v1-structured-json-core-envelope-v1"); err != nil {
			return nil, invalid("invalid CloudEvents rule")
		}
		sources, _ := array(profile["normativeSources"])
		if len(sources) != 2 || id.repository != "https://github.com/cloudevents/spec" {
			return nil, invalid("invalid CloudEvents sources")
		}
		byRole := map[string]map[string]any{}
		for _, raw := range sources {
			source, _ := object(raw)
			role, _ := stringValue(source["role"])
			byRole[role] = source
		}
		for _, role := range []string{"spec", "json-format"} {
			source := byRole[role]
			if source == nil {
				return nil, invalid("missing CloudEvents source role")
			}
			repository, _ := stringValue(source["repositoryURL"])
			sourcePath, _ := stringValue(source["path"])
			if repository != id.repository || sourcePath != map[string]string{"spec": "spec.md", "json-format": "json-format.md"}[role] {
				return nil, invalid("CloudEvents source mismatch")
			}
			commit, _ := stringValue(source["commit"])
			content, _ := stringValue(source["contentDigest"])
			spans, err := spansFromNormative(source["spans"])
			if err != nil {
				return nil, err
			}
			v, err := sourceRecord(map[string]any{"id": "cloudevents-structured-json-" + role + "-profile", "url": repository + "/blob/" + commit + "/" + sourcePath, "revision": commit, "contentDigest": content, "spans": spans}, project)
			if err != nil {
				return nil, err
			}
			evidence = append(evidence, v)
		}
		command = "cloudevents-structured-json"
		profileID = "structured-json-core-envelope-v1"
		limit = "Checks one named CloudEvents 1.0 structured JSON core-envelope subset only; it does not validate source URI semantics, source-plus-id uniqueness, data schemas, base64 decoding, extensions, batching, transport, SDK/runtime behavior, delivery, signing, or authentication."
	}
	capability := map[string]any{"kind": "standards_conformance_profile", "command": []any{"check", command}, "profileID": profileID, "metadataState": "embedded_reviewed_profile_with_optional_explicit_signed_local_selection", "profileDigest": digest, "evidence": evidence, "limit": limit}
	return map[string]any{"projectID": project, "displayName": id.name, "repositoryURL": id.repository, "supportState": "executable", "capabilities": []any{capability}, "selectedSourceRecords": []any{}}, nil
}

func tikvProject(profile map[string]any, digest string, identities map[string]identity) (map[string]any, error) {
	id, ok := identities["tikv"]
	if !ok || id.repository != "https://github.com/tikv/tikv" || profile["apiVersion"] != "prufyx.io/tikv-gcp-v2-wif-backup-profile/v1" || profile["kind"] != "TiKVGCPV2WIFBackupProfile" || profile["purpose"] != "planned_operation_preflight" || profile["engineCapabilityDigest"] != "sha256:f342ee3a3a997add0a234937499a8e2327baad4e4329b12b590e6e5fb1528d8a" || profile["revision"] != "1" {
		return nil, invalid("invalid TiKV profile")
	}
	target, _ := object(profile["target"])
	if !exactKeys(target, "component", "version") || target["component"] != "pkg:github/tikv/tikv" || target["version"] != "8.5.8" {
		return nil, invalid("invalid TiKV target")
	}
	if err := requireSingleRule(profile, "tikv-8.5.8-gcp-v2-wif-full-backup-enabled-v1"); err != nil {
		return nil, invalid("invalid TiKV rule")
	}
	sources, _ := array(profile["normativeSources"])
	if len(sources) != 3 {
		return nil, invalid("invalid TiKV sources")
	}
	byRole := map[string]map[string]any{}
	for _, raw := range sources {
		source, _ := object(raw)
		role, _ := stringValue(source["role"])
		byRole[role] = source
	}
	expected := []struct{ role, repository, path string }{{"target_setting_declaration", "https://github.com/tikv/tikv", "src/config/mod.rs"}, {"target_full_backup_caller", "https://github.com/tikv/tikv", "components/backup/src/endpoint.rs"}, {"operator_action_guidance", "https://github.com/pingcap/docs", "tikv-configuration-file.md"}}
	evidence := []any{}
	for _, want := range expected {
		source := byRole[want.role]
		if source == nil || source["repositoryURL"] != want.repository || source["path"] != want.path {
			return nil, invalid("TiKV source mismatch")
		}
		commit, _ := stringValue(source["commit"])
		content, _ := stringValue(source["contentDigest"])
		spans, err := spansFromNormative(source["spans"])
		if err != nil {
			return nil, err
		}
		v, err := sourceRecord(map[string]any{"id": "tikv-gcp-v2-wif-" + strings.ReplaceAll(want.role, "_", "-"), "url": want.repository + "/blob/" + commit + "/" + want.path, "revision": commit, "contentDigest": content, "spans": spans}, "tikv")
		if err != nil {
			return nil, err
		}
		evidence = append(evidence, v)
	}
	capability := map[string]any{"kind": "target_preflight_profile", "command": []any{"check", "tikv-gcp-v2-wif-backup"}, "target": map[string]any{"component": "pkg:github/tikv/tikv", "version": "8.5.8", "operation": "gcs-full-backup-wif"}, "profileID": "tikv-8.5.8-gcp-v2-wif-full-backup-v1", "metadataState": "embedded_reviewed_profile_with_optional_explicit_signed_local_selection", "profileDigest": digest, "evidence": evidence, "limit": "Checks one explicit TiKV 8.5.8 planned GCS WIF full-backup setting only; aggregate backup readiness, credentials, GCS access, execution, completion, restore, log backup, runtime behavior, and data safety remain UNKNOWN."}
	return map[string]any{"projectID": "tikv", "displayName": id.name, "repositoryURL": id.repository, "supportState": "executable", "capabilities": []any{capability}, "selectedSourceRecords": []any{}}, nil
}

func validateLatestCertContract(latest map[string]any) error {
	if !exactKeys(latest, "schema", "component", "target", "transitions", "originChartManifests", "removedPaths", "sources") || latest["schema"] != "prufyx.io/cert-manager-removed-monitor-values-source-contract/v1" || latest["component"] != "pkg:helm/quay.io/jetstack/charts/cert-manager" {
		return invalid("invalid latest cert contract identity")
	}
	target, targetOK := object(latest["target"])
	targetVersion, versionOK := stringValue(target["version"])
	targetDigest, digestOK := stringValue(target["chartManifestDigest"])
	targetCommit, commitOK := stringValue(target["tagCommit"])
	if !targetOK || !exactKeys(target, "version", "chartManifestDigest", "tagCommit") || !versionOK || !versionRE.MatchString(targetVersion) || !digestOK || !digestRE.MatchString(targetDigest) || !commitOK || !commitRE.MatchString(targetCommit) {
		return invalid("invalid latest cert target")
	}
	transitions, transitionsOK := array(latest["transitions"])
	origins, originsOK := array(latest["originChartManifests"])
	removed, removedOK := array(latest["removedPaths"])
	sources, sourcesOK := array(latest["sources"])
	if !transitionsOK || len(transitions) != 5 || !originsOK || len(origins) != 5 || !removedOK || len(removed) != 3 || !sourcesOK || len(sources) != 4 {
		return invalid("invalid latest cert contract cardinality")
	}
	seenTransitions := map[string]string{}
	for _, raw := range transitions {
		transition, ok := object(raw)
		current, currentOK := object(transition["current"])
		proposed, proposedOK := object(transition["target"])
		from, fromOK := stringValue(current["version"])
		fromDigest, fromDigestOK := stringValue(current["chartManifestDigest"])
		fromCommit, fromCommitOK := stringValue(current["tagCommit"])
		to, toOK := stringValue(proposed["version"])
		toDigest, toDigestOK := stringValue(proposed["chartManifestDigest"])
		toCommit, toCommitOK := stringValue(proposed["tagCommit"])
		if !ok || !currentOK || !proposedOK || !exactKeys(current, "version", "chartManifestDigest", "tagCommit") || !exactKeys(proposed, "version", "chartManifestDigest", "tagCommit") || !fromOK || !versionRE.MatchString(from) || !fromDigestOK || !digestRE.MatchString(fromDigest) || !fromCommitOK || !commitRE.MatchString(fromCommit) || !toOK || to != targetVersion || !toDigestOK || toDigest != targetDigest || !toCommitOK || toCommit != targetCommit || seenTransitions[from] != "" {
			return invalid("invalid latest cert transition")
		}
		seenTransitions[from] = fromDigest
	}
	seenOrigins := map[string]bool{}
	for _, raw := range origins {
		origin, ok := object(raw)
		version, versionOK := stringValue(origin["version"])
		content, contentOK := stringValue(origin["contentDigest"])
		revision, revisionOK := stringValue(origin["revision"])
		if !ok || !exactKeys(origin, "version", "url", "revision", "contentDigest") || !versionOK || seenTransitions[version] != content || seenOrigins[version] || !contentOK || !digestRE.MatchString(content) || !revisionOK || !commitRE.MatchString(revision) {
			return invalid("invalid latest cert origin")
		}
		if _, err := httpsURL(origin["url"], false); err != nil {
			return invalid("invalid latest cert origin URL")
		}
		seenOrigins[version] = true
	}
	for _, value := range removed {
		path, ok := stringValue(value)
		if !ok || path == "" {
			return invalid("invalid latest cert removed path")
		}
	}
	for _, raw := range sources {
		source, ok := object(raw)
		id, idOK := stringValue(source["id"])
		content, contentOK := stringValue(source["contentDigest"])
		if !ok || !idOK || !idRE.MatchString(id) || !contentOK || !digestRE.MatchString(content) {
			return invalid("invalid latest cert source")
		}
		if _, err := httpsURL(source["url"], false); err != nil {
			return invalid("invalid latest cert source URL")
		}
	}
	return nil
}

func canonical(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}
func canonicalString(value any) string { raw, _ := canonical(value); return string(raw) }

// Generate derives canonical JSON and the human-readable Markdown inventory.
func Generate(cfg Config) ([]byte, string, error) {
	paths := []string{cfg.Rules, cfg.Landscape, cfg.CertContract, cfg.PrometheusContract, cfg.SPIFFEProfile, cfg.CloudEventsProfile, cfg.TiKVProfile, cfg.SelectedSourceManifest, cfg.ProjectRules, cfg.ProjectRegistry}
	inputs := make([]loaded, len(paths))
	for i, name := range paths {
		v, err := cfg.load(name)
		if err != nil {
			return nil, "", err
		}
		inputs[i] = v
	}
	landscape := inputs[1].value
	if landscape["schema"] != "prufyx.io/cncf-landscape/v1" {
		return nil, "", invalid("invalid landscape schema")
	}
	rawIDs, ok := array(landscape["projects"])
	if !ok {
		return nil, "", invalid("missing landscape projects")
	}
	identities := map[string]identity{}
	for _, raw := range rawIDs {
		item, ok := object(raw)
		if !ok {
			return nil, "", invalid("invalid landscape identity")
		}
		slug, _ := stringValue(item["slug"])
		name, err := validText(item["name"], 240)
		repository, _ := stringValue(item["repositoryURL"])
		if !projectRE.MatchString(slug) || len(slug) > 80 || identities[slug].name != "" || err != nil {
			return nil, "", invalid("invalid landscape project")
		}
		identities[slug] = identity{name, repository}
	}
	preparerSource, preparerDigest, err := cfg.loadPreparerSource(cfg.CNCFPrepareSource)
	if err != nil {
		return nil, "", err
	}
	preparers, err := preparerProjects(preparerSource)
	if err != nil {
		return nil, "", err
	}
	generic, ruleCount, genericWithdrawn, err := genericProjects(inputs[0].value, identities, preparers)
	if err != nil {
		return nil, "", err
	}
	community, communityRuleCount, err := communityProjects(inputs[8].value, inputs[9].value)
	if err != nil {
		return nil, "", err
	}
	// The historical named contract remains the compatibility anchor. When
	// the additive latest contract is shipped beside it, include its finite
	// transition table in the generated inventory without changing the old
	// input identity or route.
	latestPath := filepath.Join(filepath.Dir(cfg.CertContract), "source-contract-v1-latest.json")
	latestContractDigest := ""
	if latest, latestErr := cfg.load(latestPath); latestErr == nil {
		if err := validateLatestCertContract(latest.value); err != nil {
			return nil, "", err
		}
		latestContractDigest = latest.digest
		if certContract, ok := object(inputs[2].value); ok {
			certContract["_latestContract"] = latest.value
			certContract["_latestDigest"] = latest.digest
		}
	} else if !errors.Is(latestErr, os.ErrNotExist) {
		return nil, "", latestErr
	}
	cert, err := namedProject(inputs[2].value, inputs[2].digest, identities, "cert-manager-values")
	if err != nil {
		return nil, "", err
	}
	prom, err := namedProject(inputs[3].value, inputs[3].digest, identities, "prometheus-mode")
	if err != nil {
		return nil, "", err
	}
	spiffe, err := conformanceProject(inputs[4].value, inputs[4].digest, identities, "spiffe")
	if err != nil {
		return nil, "", err
	}
	cloud, err := conformanceProject(inputs[5].value, inputs[5].digest, identities, "cloudevents")
	if err != nil {
		return nil, "", err
	}
	tikv, err := tikvProject(inputs[6].value, inputs[6].digest, identities)
	if err != nil {
		return nil, "", err
	}
	projects := map[string]map[string]any{}
	for _, item := range generic {
		projects[item["projectID"].(string)] = item
	}
	for _, item := range community {
		id := item["projectID"].(string)
		if projects[id] != nil {
			return nil, "", invalid("community-project capability overlaps CNCF identity")
		}
		projects[id] = item
	}
	for _, item := range []map[string]any{cert, prom, spiffe, cloud, tikv} {
		id := item["projectID"].(string)
		if existing := projects[id]; existing != nil {
			if existing["displayName"] != item["displayName"] || existing["repositoryURL"] != item["repositoryURL"] {
				return nil, "", invalid("named capability identity conflicts with rule project")
			}
			existingCaps, existingOK := array(existing["capabilities"])
			namedCaps, namedOK := array(item["capabilities"])
			if !existingOK || !namedOK || len(namedCaps) != 1 {
				return nil, "", invalid("invalid named capability union")
			}
			existing["capabilities"] = append(existingCaps, namedCaps...)
			continue
		}
		projects[id] = item
	}
	selected, provenance, err := selectedRecords(inputs[7].value)
	if err != nil {
		return nil, "", err
	}
	selectedByProject := map[string][]any{}
	for _, record := range selected {
		id := record["projectID"].(string)
		selectedByProject[id] = append(selectedByProject[id], record)
	}
	for id, records := range selectedByProject {
		if projects[id] != nil {
			projects[id]["selectedSourceRecords"] = records
			projects[id]["supportState"] = "executable_with_selected_source_records"
		} else {
			display := id
			if identities[id].name != "" {
				display = identities[id].name
			}
			projects[id] = map[string]any{"projectID": id, "displayName": display, "repositoryURL": records[0].(map[string]any)["canonicalRepositoryURL"], "supportState": "selected_source_only", "capabilities": []any{}, "selectedSourceRecords": records}
		}
	}
	names := make([]string, 0, len(projects))
	executable, sourceOnly := 0, 0
	for id, item := range projects {
		names = append(names, id)
		caps, _ := array(item["capabilities"])
		if len(caps) > 0 {
			executable++
		}
		if item["supportState"] == "selected_source_only" {
			sourceOnly++
		}
	}
	sort.Strings(names)
	projectList := make([]any, 0, len(names))
	for _, id := range names {
		projectList = append(projectList, projects[id])
	}
	inputDigests := map[string]any{"rules": inputs[0].digest, "landscape": inputs[1].digest, "certManagerSourceContract": inputs[2].digest, "prometheusSourceContract": inputs[3].digest, "spiffeX509SVIDProfile": inputs[4].digest, "cloudEventsStructuredJSONProfile": inputs[5].digest, "tikvGCPV2WIFBackupProfile": inputs[6].digest, "cncfPreparerDispatchSource": preparerDigest, "selectedSourceManifest": inputs[7].digest, "communityProjectRules": inputs[8].digest, "communityProjectRegistry": inputs[9].digest}
	if latestContractDigest != "" {
		inputDigests["certManagerLatestSourceContract"] = latestContractDigest
	}
	withdrawnRules := make([]any, 0, len(genericWithdrawn))
	for _, item := range genericWithdrawn {
		withdrawnRules = append(withdrawnRules, item)
	}
	inventory := map[string]any{"schema": Schema, "inputDigests": inputDigests, "selectedSourceProvenance": provenance, "counts": map[string]any{"cncfSourceRules": ruleCount, "cncfSourceRulesWithdrawn": len(genericWithdrawn), "cncfRuleProjects": len(generic), "communityProjectSourceRules": communityRuleCount, "communityProjectRuleProjects": len(community), "namedChecks": 2, "namedCheckProjects": 2, "conformanceProfiles": 2, "conformanceProjects": 2, "targetPreflightProfiles": 1, "targetPreflightProjects": 1, "executableProjects": executable, "selectedSourceRecords": len(selected), "selectedSourceProjects": len(selectedByProject), "selectedSourceOnlyProjects": sourceOnly}, "scope": map[string]any{"cncfRules": "embedded active CNCF source-rule pack; exact declared endpoints only", "communityProjectRules": "separate embedded maintainer-reviewed external-project registry; CNCF membership is not asserted and external updates are unavailable", "namedChecks": "embedded local source contracts; exact reviewed transitions only", "conformanceProfiles": "named standards subsets without invented from/to transitions", "targetPreflightProfiles": "named target-only planned-operation setting checks without invented from/to transitions", "selectedSourceRecords": "retained public-source records; source selection alone does not create executable upgrade support", "withdrawnRules": "rule evidence found unverifiable after publication; withdrawn from executable coverage, listed here rather than silently dropped", "wholeUpgrade": "UNKNOWN"}, "withdrawnRules": withdrawnRules, "projects": projectList}
	raw, err := canonical(inventory)
	if err != nil {
		return nil, "", err
	}
	return raw, renderMarkdown(inventory), nil
}

func markdownCell(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(value, "\\", "\\\\"), "|", "\\|"), "\r", ""), "\n", "<br>")
}
func markdownLink(label, rawURL string) string {
	return "[`" + markdownCell(label) + "`](<" + rawURL + ">)"
}
func stringSlice(value any) []string {
	items, _ := array(value)
	result := make([]string, 0, len(items))
	for _, item := range items {
		if s, ok := stringValue(item); ok {
			result = append(result, s)
		}
	}
	return result
}
func uniqueSorted(items []string) []string {
	set := map[string]bool{}
	for _, item := range items {
		set[item] = true
	}
	result := make([]string, 0, len(set))
	for item := range set {
		result = append(result, item)
	}
	sort.Strings(result)
	return result
}
func renderMarkdown(inventory map[string]any) string {
	counts := inventory["counts"].(map[string]any)
	n := func(k string) int { return counts[k].(int) }
	lines := []string{"# Community support inventory", "", "Generated by `cmd/prufyx-maintainer`; do not edit by hand.", "", "This inventory separates executable scoped checks from selected public-source records. Catalogue discovery identities are not support entries. A scoped result never proves a whole upgrade safe or runtime behavior.", "", fmt.Sprintf("- CNCF embedded source rules: **%d** across **%d** projects; **%d** withdrawn (unverifiable evidence) and excluded from executable coverage.", n("cncfSourceRules"), n("cncfRuleProjects"), n("cncfSourceRulesWithdrawn")), fmt.Sprintf("- Community-project embedded source rules: **%d** across **%d** projects; CNCF membership is not asserted.", n("communityProjectSourceRules"), n("communityProjectRuleProjects")), fmt.Sprintf("- Named local checks: **%d** across **%d** projects.", n("namedChecks"), n("namedCheckProjects")), fmt.Sprintf("- Standards-conformance profiles: **%d** across **%d** projects; these are not version-transition checks.", n("conformanceProfiles"), n("conformanceProjects")), fmt.Sprintf("- Target-preflight profiles: **%d** across **%d** projects; these are not version-transition checks.", n("targetPreflightProfiles"), n("targetPreflightProjects")), fmt.Sprintf("- Executable-project union: **%d** projects.", n("executableProjects")), fmt.Sprintf("- Selected retained public-source records: **%d** across **%d** projects; **%d** are source-only and have no executable-support capability.", n("selectedSourceRecords"), n("selectedSourceProjects"), n("selectedSourceOnlyProjects")), "", "## Executable projects", "", "| Project | Executable capability | Exact reviewed transition(s) | Pinned evidence | Local preparer | Limits |", "| --- | --- | --- | --- | --- |"}
	projects := inventory["projects"].([]any)
	for _, rawProject := range projects {
		project := rawProject.(map[string]any)
		if project["supportState"] == "selected_source_only" {
			continue
		}
		labels, transitions, preparers, limits, evidence := []string{}, []string{}, []string{}, []string{}, []string{}
		caps, _ := array(project["capabilities"])
		for _, rawCap := range caps {
			cap := rawCap.(map[string]any)
			command := stringSlice(cap["command"])
			labels = append(labels, "`prufyx "+strings.Join(command, " ")+"`")
			if cap["kind"] == "standards_conformance_profile" {
				transitions = append(transitions, "standards subset (no from/to transition)")
			}
			if cap["kind"] == "target_preflight_profile" {
				transitions = append(transitions, "target preflight (no from/to transition)")
			}
			rules, _ := array(cap["rules"])
			for _, rawRule := range rules {
				rule := rawRule.(map[string]any)
				tr := rule["transition"].(map[string]any)
				transitions = append(transitions, fmt.Sprintf("`%s` %s → %s", rule["ruleID"], tr["from"], tr["to"]))
				limits = append(limits, rule["limit"].(string))
				sources, _ := array(rule["evidence"])
				for _, rawSource := range sources {
					source := rawSource.(map[string]any)
					evidence = append(evidence, markdownLink(source["id"].(string), source["url"].(string)))
				}
			}
			trs, _ := array(cap["transitions"])
			for _, rawTr := range trs {
				tr := rawTr.(map[string]any)
				transitions = append(transitions, fmt.Sprintf("%s → %s", tr["from"], tr["to"]))
			}
			sources, _ := array(cap["evidence"])
			for _, rawSource := range sources {
				source := rawSource.(map[string]any)
				evidence = append(evidence, markdownLink(source["id"].(string), source["url"].(string)))
			}
			if rawPreparers, ok := array(cap["localPreparers"]); ok {
				for _, rawPreparer := range rawPreparers {
					preparer := rawPreparer.(map[string]any)
					preparers = append(preparers, "`prufyx "+strings.Join(stringSlice(preparer["command"]), " ")+"`")
					limits = append(limits, preparer["limit"].(string))
				}
			} else if rawPreparer, ok := cap["localPreparer"]; ok {
				preparer := rawPreparer.(map[string]any)
				preparers = append(preparers, "`prufyx "+strings.Join(stringSlice(preparer["command"]), " ")+"`")
				limits = append(limits, preparer["limit"].(string))
			}
			if limit, ok := stringValue(cap["limit"]); ok {
				limits = append(limits, limit)
			}
		}
		preparerText := "—"
		if len(preparers) > 0 {
			escaped := make([]string, len(preparers))
			for i, item := range preparers {
				escaped[i] = markdownCell(item)
			}
			preparerText = strings.Join(escaped, "<br>")
		}
		escapeJoin := func(items []string) string {
			for i := range items {
				items[i] = markdownCell(items[i])
			}
			return strings.Join(items, "<br>")
		}
		lines = append(lines, fmt.Sprintf("| [%s](<%s>) | %s | %s | %s | %s | %s |", markdownCell(project["displayName"].(string)), project["repositoryURL"], escapeJoin(labels), escapeJoin(transitions), strings.Join(uniqueSorted(evidence), "<br>"), preparerText, escapeJoin(uniqueSorted(limits))))
	}
	lines = append(lines, "", "## Selected-source-only projects", "", "These projects have retained public-source records but no executable check in this binary. They are **reference-only** and **license-unreviewed**, not upgrade support.", "", "| Project | Retained immutable source reference(s) | Metadata state |", "| --- | --- | --- |")
	found := false
	for _, rawProject := range projects {
		project := rawProject.(map[string]any)
		if project["supportState"] != "selected_source_only" {
			continue
		}
		found = true
		records, _ := array(project["selectedSourceRecords"])
		refs := make([]string, 0, len(records))
		for _, rawRecord := range records {
			record := rawRecord.(map[string]any)
			refs = append(refs, markdownLink(record["id"].(string), record["immutableURL"].(string)))
		}
		lines = append(lines, fmt.Sprintf("| %s | %s | reference-only; license-unreviewed |", markdownCell(project["projectID"].(string)), strings.Join(refs, ", ")))
	}
	if !found {
		lines = append(lines, "| — | — | — |")
	}
	lines = append(lines, "", "## Withdrawn rules", "", "These embedded source rules were found to have unverifiable evidence after publication (the recorded evidence no longer matches the corpus digest convention) and were withdrawn: their claim is always `UNKNOWN` and they establish no executable support, unlike the rules above. They are listed here, not silently dropped from this inventory.", "", "| Rule ID | Project | Family | Reason |", "| --- | --- | --- | --- |")
	withdrawnRules, _ := array(inventory["withdrawnRules"])
	if len(withdrawnRules) == 0 {
		lines = append(lines, "| — | — | — | — |")
	}
	for _, rawWithdrawn := range withdrawnRules {
		withdrawn := rawWithdrawn.(map[string]any)
		lines = append(lines, fmt.Sprintf("| `%s` | %s | %s | %s |", markdownCell(withdrawn["ruleID"].(string)), markdownCell(withdrawn["project"].(string)), markdownCell(withdrawn["family"].(string)), markdownCell(withdrawn["reasonCode"].(string))))
	}
	return strings.Join(lines, "\n") + "\n"
}
