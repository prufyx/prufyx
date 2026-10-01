// SPDX-License-Identifier: AGPL-3.0-only

// Package sourcecorpus verifies bounded retained public-source evidence and
// composes private shard collections. It never fetches or promotes evidence.
package sourcecorpus

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	Schema                        = "prufyx.io/public-source-corpus/v1"
	ReceiptSchema                 = "prufyx.io/public-source-corpus-receipt/v1"
	DeclaredAuthority             = "DECLARED_PUBLIC_SOURCE_BYTES_NOT_RULE_OR_RUNTIME_PROOF"
	LocalAuthority                = "LOCAL_RETAINED_BYTES_AND_DECLARED_METADATA_ONLY"
	CollectionSchema              = "prufyx.io/private-source-corpus-collection/v1"
	CollectionReceiptSchema       = "prufyx.io/private-source-corpus-collection-receipt/v1"
	CollectionAuthority           = "LOCAL_VERIFIED_RETAINED_SHARDS_NOT_RULE_OR_RUNTIME_PROOF"
	maxManifestBytes        int64 = 256 * 1024
	maxObjectBytes          int64 = 4 * 1024 * 1024
	maxAggregateBytes             = 16 * 1024 * 1024
	maxRecords                    = 64
	MaxSpans                      = 8
	maxRuleIDs                    = 16
	MaxSourceLines                = 1_000_000
	maxJSONDepth                  = 32
	maxJSONList                   = 512
	maxJSONKeys                   = 16
	maxText                       = 1200
	maxIndexBytes           int64 = 256 * 1024
	maxShards                     = 64
	maxCollectionRecords          = 4096
	maxObjects                    = 4096
	maxUniqueBytes                = 64 * 1024 * 1024
	maxOutputBytes                = 1 * 1024 * 1024
	maxPathBytes                  = 512
	maxPathSegments               = 16
)

var (
	errRejected            = errors.New("source corpus rejected")
	shaPattern             = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	commitPattern          = regexp.MustCompile(`^[0-9a-f]{40}$`)
	semverPattern          = regexp.MustCompile(`^(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})\.(?:0|[1-9][0-9]{0,5})$`)
	slugPattern            = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	ruleIDPattern          = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,127}$`)
	githubSegmentPattern   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,98}$`)
	gitPathSegmentPattern  = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9._+-]{0,127}$`)
	objectNamePattern      = regexp.MustCompile(`^sha256/[0-9a-f]{64}$`)
	timestampPattern       = regexp.MustCompile(`^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$`)
	surrogateEscapePattern = regexp.MustCompile(`(?i)\\u[d][89ab][0-9a-f]{2}`)
)

// Error deliberately omits paths, values, and source text.
var Error = errRejected

type objectReader func(string) ([]byte, error)

// Canonical returns the compact, sorted-key JSON encoding used by the legacy
// verifier. Valid contract data is ASCII, so its bytes match ensure_ascii JSON.
func Canonical(value any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, errRejected
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

func SHA(data []byte) string {
	digest := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(digest[:])
}

// DecodeBounded rejects duplicate keys, floats, invalid UTF-8, excessive
// depth/cardinality/text, and trailing JSON values.
func DecodeBounded(raw []byte, maximum int64) (any, error) {
	if len(raw) == 0 || int64(len(raw)) > maximum || !utf8.Valid(raw) || surrogateEscapePattern.Match(raw) {
		return nil, errRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	value, err := decodeValue(decoder, 0)
	if err != nil {
		return nil, errRejected
	}
	if _, err = decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, errRejected
	}
	return value, nil
}

func decodeValue(decoder *json.Decoder, depth int) (any, error) {
	if depth > maxJSONDepth {
		return nil, errRejected
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, errRejected
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			result := map[string]any{}
			for decoder.More() {
				if len(result) >= maxJSONKeys {
					return nil, errRejected
				}
				keyToken, keyErr := decoder.Token()
				key, ok := keyToken.(string)
				if keyErr != nil || !ok || !validString(key, 64, false) {
					return nil, errRejected
				}
				if _, exists := result[key]; exists {
					return nil, errRejected
				}
				item, itemErr := decodeValue(decoder, depth+1)
				if itemErr != nil {
					return nil, errRejected
				}
				result[key] = item
			}
			if end, endErr := decoder.Token(); endErr != nil || end != json.Delim('}') {
				return nil, errRejected
			}
			return result, nil
		case '[':
			result := []any{}
			for decoder.More() {
				if len(result) >= maxJSONList {
					return nil, errRejected
				}
				item, itemErr := decodeValue(decoder, depth+1)
				if itemErr != nil {
					return nil, errRejected
				}
				result = append(result, item)
			}
			if end, endErr := decoder.Token(); endErr != nil || end != json.Delim(']') {
				return nil, errRejected
			}
			return result, nil
		default:
			return nil, errRejected
		}
	case string:
		if !validString(value, maxText, true) {
			return nil, errRejected
		}
		return value, nil
	case json.Number:
		text := value.String()
		if len(text) > 12 || strings.ContainsAny(text, ".eE") {
			return nil, errRejected
		}
		integer, parseErr := strconv.ParseInt(text, 10, 64)
		if parseErr != nil {
			return nil, errRejected
		}
		return integer, nil
	case bool, nil:
		return value, nil
	default:
		return nil, errRejected
	}
}

func validString(value string, maximum int, multiline bool) bool {
	if value == "" || utf8.RuneCountInString(value) > maximum {
		return false
	}
	for _, character := range value {
		if character == 0x7f || character >= 0xd800 && character <= 0xdfff || character < 0x20 && (!multiline || character != '\n') {
			return false
		}
	}
	return true
}

func closed(value any, fields ...string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(fields) {
		return nil, errRejected
	}
	for _, field := range fields {
		if _, exists := object[field]; !exists {
			return nil, errRejected
		}
	}
	return object, nil
}

func text(value any, maximum int) (string, error) {
	result, ok := value.(string)
	if !ok || !validString(result, maximum, false) {
		return "", errRejected
	}
	return result, nil
}

func token(value any, pattern *regexp.Regexp, maximum int) (string, error) {
	result, err := text(value, maximum)
	if err != nil || !pattern.MatchString(result) {
		return "", errRejected
	}
	return result, nil
}

func ValidateSHA(value any) (string, error)    { return token(value, shaPattern, 71) }
func ValidateSlug(value any) (string, error)   { return token(value, slugPattern, 128) }
func ValidateCommit(value any) (string, error) { return token(value, commitPattern, 40) }
func ValidateVersion(value any) (string, error) {
	version, err := text(value, 24)
	if err != nil || version != "reference_only" && !semverPattern.MatchString(version) {
		return "", errRejected
	}
	return version, nil
}

func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= utf8.RuneSelf {
			return false
		}
	}
	return true
}

func ValidateRepository(value any) (string, error) {
	repository, err := text(value, 256)
	if err != nil || !isASCII(repository) || strings.ContainsAny(repository, "?#%\\") {
		return "", errRejected
	}
	parsed, err := url.Parse(repository)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errRejected
	}
	parts := strings.Split(parsed.EscapedPath(), "/")
	if len(parts) != 3 || parts[0] != "" || !githubSegmentPattern.MatchString(parts[1]) || !githubSegmentPattern.MatchString(parts[2]) || strings.HasSuffix(strings.ToLower(parts[2]), ".git") {
		return "", errRejected
	}
	canonical := "https://github.com/" + parts[1] + "/" + parts[2]
	if repository != canonical {
		return "", errRejected
	}
	return canonical, nil
}

func ValidateImmutableURL(value any, repository, commit string) (string, error) {
	immutable, err := text(value, 512)
	if err != nil || !isASCII(immutable) || strings.ContainsAny(immutable, "?#%\\") {
		return "", errRejected
	}
	parsed, err := url.Parse(immutable)
	if err != nil || parsed.Scheme != "https" || parsed.Host != "github.com" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errRejected
	}
	ownerRepo := strings.TrimPrefix(repository, "https://github.com/")
	prefix := "/" + ownerRepo + "/blob/" + commit + "/"
	if !strings.HasPrefix(parsed.EscapedPath(), prefix) {
		return "", errRejected
	}
	path := strings.TrimPrefix(parsed.EscapedPath(), prefix)
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return "", errRejected
	}
	for _, part := range parts {
		if !gitPathSegmentPattern.MatchString(part) {
			return "", errRejected
		}
	}
	canonical := repository + "/blob/" + commit + "/" + strings.Join(parts, "/")
	if immutable != canonical {
		return "", errRejected
	}
	return canonical, nil
}

func sourceKind(value any) (string, error) {
	kind, err := text(value, 128)
	if err != nil {
		return "", errRejected
	}
	switch kind {
	case "changelog", "release_note", "migration_guide", "source_code", "helm_chart", "repository_metadata":
		return kind, nil
	default:
		return "", errRejected
	}
}

func timestamp(value any) (string, error) {
	stamp, err := text(value, 20)
	if err != nil || !timestampPattern.MatchString(stamp) {
		return "", errRejected
	}
	parsed, err := time.Parse("2006-01-02T15:04:05Z", stamp)
	if err != nil || parsed.Format("2006-01-02T15:04:05Z") != stamp {
		return "", errRejected
	}
	return stamp, nil
}

// ValidateDeclarations validates and normalizes packet and rule references.
func ValidateDeclarations(value any) (map[string]any, error) {
	declaration, err := closed(value, "packetDigest", "ruleIDs")
	if err != nil {
		return nil, errRejected
	}
	packet := declaration["packetDigest"]
	if packet != nil {
		if _, err = ValidateSHA(packet); err != nil {
			return nil, errRejected
		}
	}
	rawRules, ok := declaration["ruleIDs"].([]any)
	if !ok || len(rawRules) > maxRuleIDs {
		return nil, errRejected
	}
	rules := make([]any, 0, len(rawRules))
	seen := map[string]struct{}{}
	for _, raw := range rawRules {
		rule, ruleErr := token(raw, ruleIDPattern, 128)
		if ruleErr != nil {
			return nil, errRejected
		}
		if _, exists := seen[rule]; exists {
			return nil, errRejected
		}
		seen[rule] = struct{}{}
		rules = append(rules, rule)
	}
	return map[string]any{"packetDigest": packet, "ruleIDs": rules}, nil
}

// ValidateSpansShape validates ordered span metadata without source bytes.
func ValidateSpansShape(value any) ([]any, error) {
	raw, ok := value.([]any)
	if !ok || len(raw) < 1 || len(raw) > MaxSpans {
		return nil, errRejected
	}
	result := make([]any, 0, len(raw))
	priorEnd := int64(0)
	for _, item := range raw {
		span, err := closed(item, "startLine", "endLine", "spanDigest")
		if err != nil {
			return nil, errRejected
		}
		start, startOK := span["startLine"].(int64)
		end, endOK := span["endLine"].(int64)
		digest, digestErr := ValidateSHA(span["spanDigest"])
		if !startOK || !endOK || digestErr != nil || start < 1 || end < start || start <= priorEnd || end > MaxSourceLines {
			return nil, errRejected
		}
		result = append(result, map[string]any{"startLine": start, "endLine": end, "spanDigest": digest})
		priorEnd = end
	}
	return result, nil
}

// VerifySpans checks exact raw-LF selection and returns normalized spans and
// their canonical digest. Bytes are never decoded or normalized.
func VerifySpans(value any, data []byte) ([]any, string, error) {
	spans, err := ValidateSpansShape(value)
	if err != nil || bytes.Count(data, []byte{'\n'})+1 > MaxSourceLines {
		return nil, "", errRejected
	}
	lines := bytes.Split(data, []byte{'\n'})
	for _, item := range spans {
		span := item.(map[string]any)
		start, end := span["startLine"].(int64), span["endLine"].(int64)
		if end > int64(len(lines)) {
			return nil, "", errRejected
		}
		selected := bytes.Join(lines[start-1:end], []byte{'\n'})
		if SHA(selected) != span["spanDigest"] {
			return nil, "", errRejected
		}
	}
	canonical, err := Canonical(spans)
	if err != nil {
		return nil, "", errRejected
	}
	return spans, SHA(canonical), nil
}

type verificationState struct {
	seenIDs      map[string]struct{}
	seenLogical  map[string]struct{}
	projects     map[string]string
	sourceMeta   map[string]string
	objectCache  map[string][]byte
	aggregate    int
	objectReader objectReader
}

func newVerificationState(reader objectReader) *verificationState {
	return &verificationState{map[string]struct{}{}, map[string]struct{}{}, map[string]string{}, map[string]string{}, map[string][]byte{}, 0, reader}
}

func (state *verificationState) validateRecord(value any) (map[string]any, error) {
	record, err := closed(value, "id", "project", "source", "capture", "declarations")
	if err != nil {
		return nil, errRejected
	}
	id, err := ValidateSlug(record["id"])
	if err != nil {
		return nil, errRejected
	}
	if _, exists := state.seenIDs[id]; exists {
		return nil, errRejected
	}
	state.seenIDs[id] = struct{}{}
	project, err := closed(record["project"], "slug", "canonicalRepositoryURL")
	if err != nil {
		return nil, errRejected
	}
	slug, err := ValidateSlug(project["slug"])
	if err != nil {
		return nil, errRejected
	}
	projectRepo, err := ValidateRepository(project["canonicalRepositoryURL"])
	if err != nil {
		return nil, errRejected
	}
	if prior, exists := state.projects[slug]; exists && prior != projectRepo {
		return nil, errRejected
	}
	state.projects[slug] = projectRepo
	source, err := closed(record["source"], "repositoryURL", "sourceKind", "version", "commit", "immutableURL", "fileDigest", "byteLength", "spans")
	if err != nil {
		return nil, errRejected
	}
	repo, err := ValidateRepository(source["repositoryURL"])
	if err != nil {
		return nil, errRejected
	}
	kind, err := sourceKind(source["sourceKind"])
	if err != nil {
		return nil, errRejected
	}
	version, err := ValidateVersion(source["version"])
	if err != nil {
		return nil, errRejected
	}
	commit, err := ValidateCommit(source["commit"])
	if err != nil {
		return nil, errRejected
	}
	immutable, err := ValidateImmutableURL(source["immutableURL"], repo, commit)
	if err != nil {
		return nil, errRejected
	}
	fileDigest, err := ValidateSHA(source["fileDigest"])
	if err != nil {
		return nil, errRejected
	}
	length, ok := source["byteLength"].(int64)
	if !ok || length < 1 || length > maxObjectBytes {
		return nil, errRejected
	}
	capture, err := closed(record["capture"], "capturedAt", "object")
	if err != nil {
		return nil, errRejected
	}
	capturedAt, err := timestamp(capture["capturedAt"])
	if err != nil {
		return nil, errRejected
	}
	objectName, err := text(capture["object"], 71)
	if err != nil || objectName != "sha256/"+strings.TrimPrefix(fileDigest, "sha256:") {
		return nil, errRejected
	}
	data, exists := state.objectCache[objectName]
	if !exists {
		data, err = state.objectReader(objectName)
		if err != nil || int64(len(data)) != length || SHA(data) != fileDigest {
			return nil, errRejected
		}
		state.objectCache[objectName] = data
		state.aggregate += len(data)
		if state.aggregate > maxAggregateBytes {
			return nil, errRejected
		}
	} else if int64(len(data)) != length || SHA(data) != fileDigest {
		return nil, errRejected
	}
	_, spansDigest, err := VerifySpans(source["spans"], data)
	if err != nil {
		return nil, errRejected
	}
	logical := slug + "\x00" + immutable + "\x00" + spansDigest
	if _, exists = state.seenLogical[logical]; exists {
		return nil, errRejected
	}
	state.seenLogical[logical] = struct{}{}
	meta := strings.Join([]string{repo, kind, version, fileDigest, strconv.FormatInt(length, 10)}, "\x00")
	if prior, found := state.sourceMeta[immutable]; found && prior != meta {
		return nil, errRejected
	}
	state.sourceMeta[immutable] = meta
	declarations, err := ValidateDeclarations(record["declarations"])
	if err != nil {
		return nil, errRejected
	}
	return map[string]any{
		"id":           id,
		"project":      map[string]any{"slug": slug, "canonicalRepositoryURL": projectRepo},
		"source":       map[string]any{"repositoryURL": repo, "sourceKind": kind, "version": version, "commit": commit, "immutableURL": immutable, "fileDigest": fileDigest, "byteLength": length, "spansDigest": spansDigest},
		"capture":      map[string]any{"capturedAt": capturedAt, "objectDigest": fileDigest},
		"declarations": declarations,
	}, nil
}

func verifyValue(manifest any, reader objectReader) (map[string]any, error) {
	document, err := closed(manifest, "schema", "revision", "authority", "records")
	if err != nil || document["schema"] != Schema || document["authority"] != DeclaredAuthority {
		return nil, errRejected
	}
	revision, err := ValidateSlug(document["revision"])
	if err != nil {
		return nil, errRejected
	}
	records, ok := document["records"].([]any)
	if !ok || len(records) < 1 || len(records) > maxRecords {
		return nil, errRejected
	}
	state := newVerificationState(reader)
	verified := make([]any, 0, len(records))
	for _, item := range records {
		record, recordErr := state.validateRecord(item)
		if recordErr != nil {
			return nil, errRejected
		}
		verified = append(verified, record)
	}
	canonicalManifest, err := Canonical(document)
	if err != nil {
		return nil, errRejected
	}
	return map[string]any{
		"schema": ReceiptSchema, "manifestDigest": SHA(canonicalManifest), "revision": revision,
		"verification": "VERIFIED_RETAINED_BYTES", "authority": LocalAuthority,
		"recordCount": int64(len(verified)), "aggregateByteLength": int64(state.aggregate), "records": verified,
		"limitations": []any{
			"verification is local retained-byte consistency only; it does not fetch or authenticate upstream sources, commits, tags, or licenses",
			"project, packet, and rule references are declarations only; this receipt does not approve catalogue identity, coverage, rules, runtime behavior, signing, or publication",
			"retained source objects are private evidence inputs and are not a client package, TUF target, or training authorization",
		},
	}, nil
}

// Verify verifies a decoded manifest against an object root and returns the
// exact canonical receipt without a trailing newline.
func Verify(raw []byte, objectRoot string) ([]byte, error) {
	manifest, err := DecodeBounded(raw, maxManifestBytes)
	if err != nil {
		return nil, errRejected
	}
	root, err := openPhysical(objectRoot, os.O_RDONLY)
	if err != nil {
		return nil, errRejected
	}
	defer root.Close()
	state, err := stateOf(root)
	if err != nil || !state.mode.IsDir() {
		return nil, errRejected
	}
	shaDir, err := openRelativeDirectory(root, "sha256")
	if err != nil {
		return nil, errRejected
	}
	defer shaDir.Close()
	reader := func(name string) ([]byte, error) {
		if !objectNamePattern.MatchString(name) {
			return nil, errRejected
		}
		file, openErr := openRelative(shaDir, strings.TrimPrefix(name, "sha256/"), os.O_RDONLY)
		if openErr != nil {
			return nil, errRejected
		}
		defer file.Close()
		return readRegular(file, maxObjectBytes, false)
	}
	receipt, err := verifyValue(manifest, reader)
	if err != nil {
		return nil, errRejected
	}
	return Canonical(receipt)
}

// VerifyPath safely reads a manifest and verifies its object root.
func VerifyPath(manifestPath, objectRoot string) ([]byte, error) {
	raw, err := readPhysicalFile(manifestPath, maxManifestBytes, false)
	if err != nil {
		return nil, errRejected
	}
	return Verify(raw, objectRoot)
}

// Run is the redacted command adapter for the future maintainer CLI.
func Run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 5 && args[0] == "verify" && args[1] == "--manifest" && args[3] == "--object-root" {
		receipt, err := VerifyPath(args[2], args[4])
		if err == nil {
			if written, writeErr := stdout.Write(append(receipt, '\n')); writeErr == nil && written == len(receipt)+1 {
				return 0
			}
		}
	} else if len(args) == 5 && args[0] == "verify-collection" && args[1] == "--root" && args[3] == "--index" {
		receipt, err := VerifyCollection(args[2], args[4])
		if err == nil {
			if written, writeErr := stdout.Write(append(receipt, '\n')); writeErr == nil && written == len(receipt)+1 {
				return 0
			}
		}
	}
	_, _ = io.WriteString(stderr, "source-corpus: corpus rejected\n")
	return 2
}
