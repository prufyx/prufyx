// SPDX-License-Identifier: AGPL-3.0-only

package fix

import (
	"regexp"

	"gopkg.in/yaml.v3"
)

// The decode proof reads YAML 1.2 (yaml.v3), but Kubernetes clients read
// plain scalars with YAML 1.1 rules, where more spellings are not strings.
// A plain replacement is therefore refused when 1.1 would read it as
// anything but text, unless both readings agree it is the same plain decimal
// number. A quoted replacement is always text for both and is fine.

var (
	// yaml11Words are the 1.1 spellings of booleans and null, in any case.
	yaml11Words = regexp.MustCompile(`^(?i:y|yes|n|no|true|false|on|off|null|~)$`)
	// yaml11Numbers covers the 1.1 integer and float forms that 1.2 reads
	// differently or not at all: underscores, binary, octal (with a leading
	// 0 or 0o), hexadecimal, sexagesimal (1:20), exponents, .inf and .nan.
	yaml11Numbers = regexp.MustCompile(`^[-+]?(?:` +
		`0b[01_]+|0o?[0-7_]+|0x[0-9a-fA-F_]+|` + // binary, octal, hex
		`(?:0|[1-9][0-9_]*)|` + // decimal, possibly with underscores
		`[1-9][0-9_]*(?::[0-5]?[0-9])+(?:\.[0-9_]*)?|` + // sexagesimal
		`(?:[0-9][0-9_]*)?\.[0-9_]*(?:[eE][-+]?[0-9]+)?|` + // floats
		`[0-9][0-9_]*[eE][-+]?[0-9]+|` + // exponent without a dot
		`\.(?i:inf|nan))$`)
	// yaml11Timestamp covers the 1.1 date and date-time forms.
	yaml11Timestamp = regexp.MustCompile(`^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:(?:[Tt]|[ \t]+)[0-9]{1,2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9]{1,2}(?::[0-9]{2})?))?)?$`)
	// plainDecimal is the one numeric spelling both readings agree on.
	plainDecimal = regexp.MustCompile(`^[-+]?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$`)
)

// ambiguousPlain reports a plain scalar that 1.1 would not read as the text
// that it holds, or that is a boolean, null or date for either reading.
func ambiguousPlain(node *yaml.Node) bool {
	text := node.Value
	switch node.ShortTag() {
	case "!!int", "!!float":
		return !plainDecimal.MatchString(text)
	case "!!str":
		return yaml11Words.MatchString(text) || yaml11Numbers.MatchString(text) || yaml11Timestamp.MatchString(text)
	}
	// Booleans, null and timestamps.
	return true
}
