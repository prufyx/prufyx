// SPDX-License-Identifier: AGPL-3.0-only

package knowledge

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	maxJSONDepth   = 12
	maxJSONMembers = 512
	maxJSONString  = 8192
)

var tufStaticKeys = map[string]struct{}{
	"signed": {}, "signatures": {}, "keyid": {}, "sig": {}, "_type": {}, "spec_version": {}, "version": {}, "expires": {},
	"consistent_snapshot": {}, "keys": {}, "roles": {}, "keytype": {}, "scheme": {}, "keyval": {}, "public": {}, "keyids": {}, "threshold": {},
	"meta": {}, "length": {}, "hashes": {}, "targets": {}, "custom": {}, "delegations": {},
	"root": {}, "timestamp": {}, "snapshot": {}, "targets.json": {}, "snapshot.json": {}, "sha256": {}, TargetPath: {},
}
var hexKeyRE = regexp.MustCompile(`^[0-9a-f]{64}$`)
var tufSpecRE = regexp.MustCompile(`^1\.0\.[0-9]+$`)

// validateTUFJSON rejects encoding/json's case-insensitive aliases and duplicate
// key behavior before go-tuf sees metadata. This POUF permits no extension
// fields; dynamic object keys are limited to lowercase SHA-256 key IDs.
func validateTUFJSON(raw []byte) error {
	return validateTUFJSONForTarget(raw, TargetPath)
}

func validateTUFJSONForTarget(raw []byte, targetPath string) error {
	if targetPath == "" {
		return ErrIntegrity
	}
	if len(raw) == 0 || len(raw) > maxStateFile || !utf8.Valid(raw) {
		return ErrIntegrity
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	members := 0
	if err := walkJSONTarget(d, 0, &members, targetPath); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return ErrIntegrity
	}
	return validateTUFShapeForTarget(raw, targetPath)
}

func validateTUFShape(raw []byte) error {
	return validateTUFShapeForTarget(raw, TargetPath)
}

func validateTUFShapeForTarget(raw []byte, targetPath string) error {
	var top map[string]json.RawMessage
	if json.Unmarshal(raw, &top) != nil || !exactKeys(top, []string{"signed", "signatures"}) {
		return ErrIntegrity
	}
	var signatures []map[string]json.RawMessage
	if json.Unmarshal(top["signatures"], &signatures) != nil || len(signatures) < 1 || len(signatures) > 32 {
		return ErrIntegrity
	}
	for _, s := range signatures {
		if !exactKeys(s, []string{"keyid", "sig"}) {
			return ErrIntegrity
		}
		var keyID, signature string
		if !decodeJSONString(s["keyid"], &keyID) || !hexKeyRE.MatchString(keyID) || !decodeJSONString(s["sig"], &signature) || !isLowerHex(signature, 128) {
			return ErrIntegrity
		}
	}
	var signed map[string]json.RawMessage
	if json.Unmarshal(top["signed"], &signed) != nil {
		return ErrIntegrity
	}
	var role string
	if json.Unmarshal(signed["_type"], &role) != nil {
		return ErrIntegrity
	}
	var spec, expires string
	var version int64
	if !decodeJSONString(signed["spec_version"], &spec) || !validTUFSpec(spec) || !decodePositiveInt(signed["version"], maxRevision, &version) || !decodeJSONString(signed["expires"], &expires) {
		return ErrIntegrity
	}
	if _, e := parseTime(expires); e != nil {
		return ErrIntegrity
	}
	common := []string{"_type", "spec_version", "version", "expires"}
	switch role {
	case "root":
		if !exactKeys(signed, append(common, "consistent_snapshot", "keys", "roles")) {
			return ErrIntegrity
		}
		var consistent bool
		if !decodeJSONBool(signed["consistent_snapshot"], &consistent) {
			return ErrIntegrity
		}
		var keys map[string]map[string]json.RawMessage
		if json.Unmarshal(signed["keys"], &keys) != nil {
			return ErrIntegrity
		}
		for id, k := range keys {
			if !hexKeyRE.MatchString(id) || !exactKeys(k, []string{"keytype", "scheme", "keyval"}) {
				return ErrIntegrity
			}
			var keyType, scheme string
			if !decodeJSONString(k["keytype"], &keyType) || keyType != "ed25519" || !decodeJSONString(k["scheme"], &scheme) || scheme != "ed25519" {
				return ErrIntegrity
			}
			var kv map[string]json.RawMessage
			if json.Unmarshal(k["keyval"], &kv) != nil || !exactKeys(kv, []string{"public"}) {
				return ErrIntegrity
			}
			var public string
			if !decodeJSONString(kv["public"], &public) || !isLowerHex(public, 64) {
				return ErrIntegrity
			}
		}
		var roles map[string]map[string]json.RawMessage
		if json.Unmarshal(signed["roles"], &roles) != nil {
			return ErrIntegrity
		}
		for name, r := range roles {
			if name != "root" && name != "timestamp" && name != "snapshot" && name != "targets" {
				return ErrIntegrity
			}
			if !exactKeys(r, []string{"keyids", "threshold"}) {
				return ErrIntegrity
			}
			var keyIDs []string
			var threshold int64
			if !decodeStringArray(r["keyids"], &keyIDs) || len(keyIDs) < 1 || len(keyIDs) > 32 || !decodePositiveInt(r["threshold"], int64(len(keyIDs)), &threshold) {
				return ErrIntegrity
			}
			seen := map[string]bool{}
			for _, id := range keyIDs {
				if !hexKeyRE.MatchString(id) || seen[id] {
					return ErrIntegrity
				}
				seen[id] = true
			}
		}
	case "timestamp":
		if !exactKeys(signed, append(common, "meta")) || validateMetaShape(signed["meta"], "snapshot.json") != nil {
			return ErrIntegrity
		}
	case "snapshot":
		if !exactKeys(signed, append(common, "meta")) || validateMetaShape(signed["meta"], "targets.json") != nil {
			return ErrIntegrity
		}
	case "targets":
		if !exactKeys(signed, append(common, "targets")) {
			return ErrIntegrity
		}
		var targets map[string]map[string]json.RawMessage
		if json.Unmarshal(signed["targets"], &targets) != nil || len(targets) != 1 {
			return ErrIntegrity
		}
		f, ok := targets[targetPath]
		var length int64
		if !ok || !exactKeys(f, []string{"length", "hashes"}) || !decodePositiveInt(f["length"], maxPackageEntry, &length) || validateHashesShape(f["hashes"]) != nil {
			return ErrIntegrity
		}
	default:
		return ErrIntegrity
	}
	return nil
}
func exactKeys(m map[string]json.RawMessage, want []string) bool {
	if len(m) != len(want) {
		return false
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			return false
		}
	}
	return true
}
func validateMetaShape(raw json.RawMessage, name string) error {
	var m map[string]map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil || len(m) != 1 {
		return ErrIntegrity
	}
	f, ok := m[name]
	var version, length int64
	if !ok || !exactKeys(f, []string{"version", "length", "hashes"}) || !decodePositiveInt(f["version"], maxRevision, &version) || !decodePositiveInt(f["length"], maxStateFile, &length) {
		return ErrIntegrity
	}
	return validateHashesShape(f["hashes"])
}
func validateHashesShape(raw json.RawMessage) error {
	var h map[string]json.RawMessage
	var digest string
	if json.Unmarshal(raw, &h) != nil || !exactKeys(h, []string{"sha256"}) || !decodeJSONString(h["sha256"], &digest) || !hexKeyRE.MatchString(digest) {
		return ErrIntegrity
	}
	return nil
}

func decodeJSONString(raw json.RawMessage, out *string) bool {
	return len(raw) >= 2 && raw[0] == '"' && json.Unmarshal(raw, out) == nil && len(*out) <= maxJSONString
}

func decodeJSONBool(raw json.RawMessage, out *bool) bool {
	switch {
	case bytes.Equal(raw, []byte("true")):
		*out = true
		return true
	case bytes.Equal(raw, []byte("false")):
		*out = false
		return true
	default:
		return false
	}
}

func decodePositiveInt(raw json.RawMessage, max int64, out *int64) bool {
	if len(raw) == 0 || len(raw) > 10 || raw[0] < '1' || raw[0] > '9' {
		return false
	}
	for _, c := range raw[1:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	n, err := strconv.ParseInt(string(raw), 10, 64)
	if err != nil || n < 1 || n > max {
		return false
	}
	*out = n
	return true
}

func decodeStringArray(raw json.RawMessage, out *[]string) bool {
	if len(raw) < 2 || raw[0] != '[' || json.Unmarshal(raw, out) != nil {
		return false
	}
	for _, value := range *out {
		if value == "" || len(value) > maxJSONString {
			return false
		}
	}
	return true
}

func validTUFSpec(spec string) bool {
	if !tufSpecRE.MatchString(spec) {
		return false
	}
	patch := strings.TrimPrefix(spec, "1.0.")
	n, err := strconv.ParseUint(patch, 10, 16)
	return err == nil && n <= 999 && strconv.FormatUint(n, 10) == patch
}

func isLowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
func walkJSON(d *json.Decoder, depth int, members *int) error {
	return walkJSONTarget(d, depth, members, TargetPath)
}

func walkJSONTarget(d *json.Decoder, depth int, members *int, targetPath string) error {
	if depth > maxJSONDepth {
		return ErrIntegrity
	}
	tok, err := d.Token()
	if err != nil {
		return ErrIntegrity
	}
	switch v := tok.(type) {
	case json.Delim:
		switch v {
		case '{':
			seen := map[string]bool{}
			folded := map[string]bool{}
			for d.More() {
				kTok, e := d.Token()
				if e != nil {
					return ErrIntegrity
				}
				k, ok := kTok.(string)
				if !ok || len(k) > maxJSONString || !validTUFKeyForTarget(k, targetPath) || seen[k] || folded[strings.ToLower(k)] {
					return ErrIntegrity
				}
				seen[k] = true
				folded[strings.ToLower(k)] = true
				*members++
				if *members > maxJSONMembers {
					return ErrIntegrity
				}
				if e = walkJSONTarget(d, depth+1, members, targetPath); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim('}') {
				return ErrIntegrity
			}
		case '[':
			items := 0
			for d.More() {
				items++
				*members++
				if items > maxJSONMembers || *members > maxJSONMembers {
					return ErrIntegrity
				}
				if e := walkJSONTarget(d, depth+1, members, targetPath); e != nil {
					return e
				}
			}
			end, e := d.Token()
			if e != nil || end != json.Delim(']') {
				return ErrIntegrity
			}
		default:
			return ErrIntegrity
		}
	case string:
		if len(v) > maxJSONString {
			return ErrIntegrity
		}
	case json.Number:
		s := string(v)
		if len(s) > 19 || strings.HasPrefix(s, "-") || (len(s) > 1 && s[0] == '0') || strings.ContainsAny(s, ".eE") {
			return ErrIntegrity
		}
		if _, e := strconv.ParseUint(s, 10, 63); e != nil {
			return ErrIntegrity
		}
	case bool, nil:
	default:
		return fmt.Errorf("JSON token: %w", ErrIntegrity)
	}
	return nil
}
func validTUFKey(k string) bool {
	return validTUFKeyForTarget(k, TargetPath)
}

func validTUFKeyForTarget(k, targetPath string) bool {
	if _, ok := tufStaticKeys[k]; ok {
		return true
	}
	if k == targetPath {
		return true
	}
	return hexKeyRE.MatchString(k)
}
