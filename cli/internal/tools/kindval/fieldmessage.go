// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"strings"
)

// Message patterns a refusal of a crd-field object can match.
const (
	patternUnknownField     = "unknown-field"
	patternRequiredValue    = "required-value"
	patternTypeInvalid      = "type-invalid"
	patternUnsupportedValue = "unsupported-value"
	patternInvalidValue     = "invalid-value"
	patternTooLong          = "too-long"
	patternTooMany          = "too-many"
)

const (
	strictPrefix  = "Error from server (BadRequest)"
	strictMarker  = "strict decoding error: "
	invalidMarker = `" is invalid`
	typeMarker    = "in body must be of type"
)

// fieldAnswer classifies a kubectl answer to a crd-field object. Message is
// the whole stderr, trimmed, bounded to maxFieldMessage bytes.
//
// accepted: exit 0. error (no answer): exit < 0, kubectl's client-side
// validation, or stderr that carries no sign of a server answer. An answer
// is "Error from server (", a `The <Kind> "<name>" is invalid` line, or one
// of the REST mapper's answers (not_served). An API server that could not
// handle the request (ServiceUnavailable, Timeout, TooManyRequests,
// InternalError, etcd) gave no answer to the object: error. Unlike classify,
// a failure that names a webhook (a conversion webhook that is not installed)
// is an answer: rejected.
func fieldAnswer(exit int, stderr string) ServerTry {
	msg := strings.TrimSpace(stderr)
	bounded := msg
	if len(bounded) > maxFieldMessage {
		bounded = bounded[:maxFieldMessage]
	}
	switch {
	case exit == 0:
		return ServerTry{Outcome: ServerAccepted}
	case exit < 0, strings.HasPrefix(msg, `error: error validating "STDIN"`):
		return ServerTry{Outcome: ServerError, Message: bounded}
	case strings.Contains(msg, "no matches for kind") || strings.Contains(msg, "the server doesn't have a resource type") || strings.Contains(msg, "could not find the requested resource"):
		return ServerTry{Outcome: ServerNotServed, Message: bounded}
	case serverUnavailable(msg):
		return ServerTry{Outcome: ServerError, Message: bounded}
	case strings.Contains(msg, "Error from server (") || invalidLine(msg) >= 0:
		return ServerTry{Outcome: ServerRejected, Message: bounded}
	}
	return ServerTry{Outcome: ServerError, Message: bounded}
}

// serverUnavailable reports an API server that answered that it could not
// handle the request (overloaded, timed out, storage failure): no reading of
// the object, so no answer to it. A failure that names a webhook is the
// webhook's answer, kept as a refusal.
func serverUnavailable(msg string) bool {
	if strings.Contains(msg, "webhook") {
		return false
	}
	for _, status := range []string{"Error from server (ServiceUnavailable)", "Error from server (Timeout)", "Error from server (TooManyRequests)", "Error from server (InternalError)", "etcdserver:"} {
		if strings.Contains(msg, status) {
			return true
		}
	}
	return false
}

// invalidLine is the index of the first `The <Kind> "<name>" is invalid`
// line of msg, -1 when there is none.
func invalidLine(msg string) int {
	for i, line := range strings.Split(msg, "\n") {
		if strings.HasPrefix(line, "The ") && strings.Contains(line, invalidMarker) {
			return i
		}
	}
	return -1
}

// fieldMatch is the reading of a refusal for one claim.
type fieldMatch struct {
	Pattern string   // the matched pattern name, "" when no match
	Other   []string // causes on other paths (verbatim "<field>: <body>" or `unknown field "<p>"`), in message order
	Note    string   // when Pattern is "": why
}

// cause is one schema cause: the field the server names and what it says.
type cause struct {
	Field, Body string
}

// matchField reads a refusal message for change at serverPath. A match is
// exact: every cause on serverPath must read as the change, and anything
// the reading cannot parse is no match.
func matchField(change, serverPath, message string) fieldMatch {
	if !fieldChanges[change] {
		return fieldMatch{Note: fmt.Sprintf("unknown change %q", change)}
	}
	if serverPath == "" {
		return fieldMatch{Note: "no server path"}
	}
	if len(message) >= maxFieldMessage {
		return fieldMatch{Note: "the message is truncated"}
	}
	if entries, tail, ok := strictEntries(message); ok {
		return matchStrict(change, serverPath, entries, tail)
	}
	causes, note := schemaCauses(message)
	if note != "" {
		return fieldMatch{Note: note}
	}
	return matchSchema(change, serverPath, causes)
}

// strictEntries reads the strict-decoding list of a BadRequest answer: the
// entries, the list as printed, and whether the message is one.
func strictEntries(message string) ([]string, string, bool) {
	for _, line := range strings.Split(message, "\n") {
		if !strings.HasPrefix(line, strictPrefix) {
			continue
		}
		i := strings.Index(line, strictMarker)
		if i < 0 {
			continue
		}
		tail := strings.TrimSpace(line[i+len(strictMarker):])
		if tail == "" {
			return nil, "", false
		}
		return strings.Split(tail, ", "), tail, true
	}
	return nil, "", false
}

// unknownField is the path of an `unknown field "<p>"` entry.
func unknownField(entry string) (string, bool) {
	const pre = `unknown field "`
	if !strings.HasPrefix(entry, pre) || !strings.HasSuffix(entry, `"`) || len(entry) < len(pre)+2 {
		return "", false
	}
	return entry[len(pre) : len(entry)-1], true
}

// canonicalPath spells a server path one way. The API server names an array
// element two ways: strict decoding and x-kubernetes-validations rules write
// spec.ports[0].name, the schema validation causes (kube-openapi) write
// spec.ports.0.name. A map value is spec.labels.team in both. An index in
// brackets becomes a dot segment; anything else in brackets is kept as is
// (and so never equals a dotted path).
func canonicalPath(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); i++ {
		if p[i] == '[' {
			j := i + 1
			for j < len(p) && p[j] >= '0' && p[j] <= '9' {
				j++
			}
			if j > i+1 && j < len(p) && p[j] == ']' {
				b.WriteString("." + p[i+1:j])
				i = j
				continue
			}
		}
		b.WriteByte(p[i])
	}
	return b.String()
}

// samePath reports whether two server paths name the same field, whatever
// the spelling of their array indexes. Different indexes never match.
func samePath(a, b string) bool { return canonicalPath(a) == canonicalPath(b) }

// isAncestor reports whether p names an ancestor of path.
func isAncestor(p, path string) bool {
	return strings.HasPrefix(canonicalPath(path), canonicalPath(p)+".")
}

func matchStrict(change, serverPath string, entries []string, tail string) fieldMatch {
	var m fieldMatch
	exact := false
	ancestor := ""
	for _, e := range entries {
		p, ok := unknownField(e)
		if ok && samePath(p, serverPath) {
			exact = true
			continue
		}
		if ok && ancestor == "" && isAncestor(p, serverPath) {
			ancestor = p
		}
		m.Other = append(m.Other, e)
	}
	switch {
	case change != ChangeFieldRemoved:
		m.Note = "To refuses an unknown field: " + tail
	case exact:
		m.Pattern = patternUnknownField
	case ancestor != "":
		m.Note = fmt.Sprintf("the ancestor %s is refused", ancestor)
	default:
		m.Note = fmt.Sprintf("no unknown field %q", serverPath)
	}
	return m
}

// schemaCauses reads the causes of a `The <Kind> "<name>" is invalid`
// answer; note says why there are none.
func schemaCauses(message string) ([]cause, string) {
	lines := strings.Split(message, "\n")
	at := invalidLine(message)
	if at < 0 {
		return nil, "no strict-decoding or schema refusal in the message"
	}
	head := lines[at]
	rest := strings.TrimSpace(head[strings.Index(head, invalidMarker)+len(invalidMarker):])
	if !strings.HasPrefix(rest, ":") {
		return nil, "the refusal has no causes"
	}
	rest = strings.TrimSpace(rest[1:])
	var raw []string
	if rest != "" {
		if strings.HasPrefix(rest, "[") {
			return nil, "the causes are an aggregate [...] list, not parsed"
		}
		if at+1 < len(lines) && strings.TrimSpace(strings.Join(lines[at+1:], "")) != "" {
			return nil, "unexpected lines after a single-cause refusal"
		}
		raw = []string{rest}
	} else {
		for _, line := range lines[at+1:] {
			line = strings.TrimRight(line, " \t\r")
			if line == "" {
				continue
			}
			if !strings.HasPrefix(line, "* ") {
				return nil, fmt.Sprintf("unexpected line in the causes: %q", line)
			}
			raw = append(raw, line[2:])
		}
	}
	if len(raw) == 0 {
		return nil, "the refusal has no causes"
	}
	causes := make([]cause, 0, len(raw))
	for _, r := range raw {
		i := strings.Index(r, ": ")
		if i <= 0 {
			return nil, fmt.Sprintf("a cause without a field: %q", r)
		}
		causes = append(causes, cause{Field: r[:i], Body: r[i+2:]})
	}
	return causes, ""
}

func matchSchema(change, serverPath string, causes []cause) fieldMatch {
	var m fieldMatch
	var on []cause
	for _, c := range causes {
		if samePath(c.Field, serverPath) {
			on = append(on, c)
		} else {
			m.Other = append(m.Other, c.Field+": "+c.Body)
		}
	}
	if change == ChangeFieldRemoved {
		m.Note = "To refuses by its schema, not as an unknown field"
		return m
	}
	if len(on) == 0 {
		m.Note = fmt.Sprintf("no cause on %s", serverPath)
		for _, c := range causes {
			if isAncestor(c.Field, serverPath) {
				m.Note = fmt.Sprintf("the ancestor %s is refused", c.Field)
				break
			}
			if isAncestor(serverPath, c.Field) {
				m.Note = fmt.Sprintf("the descendant %s is refused", c.Field)
				break
			}
		}
		return m
	}
	pattern := ""
	for _, c := range on {
		p, note := causePattern(change, c.Body)
		if p == "" {
			m.Note = fmt.Sprintf("%s: %s", serverPath, note)
			return m
		}
		if pattern == "" {
			pattern = p
		}
	}
	m.Pattern = pattern
	return m
}

// causePattern reads one cause body on the claim's path for change; note
// says why it does not match.
func causePattern(change, body string) (string, string) {
	typeErr := strings.HasPrefix(body, "Invalid value") && strings.Contains(body, typeMarker)
	switch change {
	case ChangeRequiredAdded:
		if strings.HasPrefix(body, "Required value") {
			return patternRequiredValue, ""
		}
	case ChangeTypeChanged:
		if typeErr {
			return patternTypeInvalid, ""
		}
	case ChangeEnumValueRemoved:
		if strings.HasPrefix(body, "Unsupported value") {
			return patternUnsupportedValue, ""
		}
	case ChangeValidationTightened:
		switch {
		case typeErr:
			return "", "looks like " + ChangeTypeChanged
		case strings.HasPrefix(body, "Invalid value"):
			return patternInvalidValue, ""
		case strings.HasPrefix(body, "Too long"):
			return patternTooLong, ""
		case strings.HasPrefix(body, "Too many"):
			return patternTooMany, ""
		}
	}
	return "", fmt.Sprintf("%q does not read as %s", body, change)
}
