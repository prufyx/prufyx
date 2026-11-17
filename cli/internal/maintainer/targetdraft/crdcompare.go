// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
)

// Full decoded-spec comparison of definitions (used by the install-path copy check).

// canonSpec writes the canonical structural encoding of a decoded YAML value:
// maps by sorted key, every scalar with its decoded type. Nothing is
// normalised (no default filling, no int/float/string unification); any value
// of an unexpected type is an error, which the caller treats as not equal.
func canonSpec(b *bytes.Buffer, v any) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("n;")
	case bool:
		b.WriteString("b:" + strconv.FormatBool(x) + ";")
	case int:
		b.WriteString("i:" + strconv.FormatInt(int64(x), 10) + ";")
	case int64:
		b.WriteString("i:" + strconv.FormatInt(x, 10) + ";")
	case uint64:
		b.WriteString("u:" + strconv.FormatUint(x, 10) + ";")
	case float64:
		b.WriteString("f:" + strconv.FormatFloat(x, 'g', -1, 64) + ";")
	case string:
		b.WriteString("s:" + strconv.Quote(x) + ";")
	case []any:
		b.WriteString("[")
		for _, e := range x {
			if err := canonSpec(b, e); err != nil {
				return err
			}
		}
		b.WriteString("]")
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString("{")
		for _, k := range keys {
			b.WriteString("k:" + strconv.Quote(k) + "=")
			if err := canonSpec(b, x[k]); err != nil {
				return err
			}
		}
		b.WriteString("}")
	default:
		return fmt.Errorf("unsupported value type %T", v)
	}
	return nil
}

func sumHex(b []byte) string {
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:])
}

// specDigest returns the digest of a definition (apiVersion and the whole
// spec) and the digest of each top-level part. Empty digest: not computable,
// never equal to anything.
func specDigest(apiVersion, spec any) (string, map[string]string) {
	m, ok := spec.(map[string]any)
	if !ok {
		return "", nil
	}
	parts := map[string]string{}
	var ab bytes.Buffer
	if err := canonSpec(&ab, apiVersion); err != nil {
		return "", nil
	}
	parts["apiVersion"] = sumHex(ab.Bytes())
	for k, v := range m {
		var pb bytes.Buffer
		if err := canonSpec(&pb, v); err != nil {
			return "", nil
		}
		parts["spec."+k] = sumHex(pb.Bytes())
	}
	names := make([]string, 0, len(parts))
	for k := range parts {
		names = append(names, k)
	}
	sort.Strings(names)
	var all bytes.Buffer
	for _, k := range names {
		all.WriteString(strconv.Quote(k) + "=" + parts[k] + "\n")
	}
	return sumHex(all.Bytes()), parts
}

// firstDifference names the first top-level part (sorted) in which two
// definitions differ, or says that a digest is missing.
func firstDifference(a, b crd) string {
	if a.SpecDigest == "" || b.SpecDigest == "" {
		return "spec digest not computable"
	}
	set := map[string]bool{}
	for k := range a.SpecParts {
		set[k] = true
	}
	for k := range b.SpecParts {
		set[k] = true
	}
	var ks []string
	for k := range set {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	for _, k := range ks {
		if a.SpecParts[k] != b.SpecParts[k] {
			return k
		}
	}
	return "unknown"
}

// crdsEqual is the comparator: both full-spec digests exist and are identical.
// It is a single function so a test can prove that weakening it is caught.
var crdsEqual = func(a, b crd) bool {
	return a.SpecDigest != "" && a.SpecDigest == b.SpecDigest
}

// Rank classes of a copy, lower wins. The table is a literal, pinned by a test
// and never read from repository content. The choice among byte-equal copies
func crdKey(c crd) string { return c.Group + "/" + c.Kind }
