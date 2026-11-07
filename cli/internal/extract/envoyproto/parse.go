// SPDX-License-Identifier: AGPL-3.0-only

package envoyproto

import (
	"fmt"
	"strconv"
	"strings"
)

// maxFieldNumber is the largest legal proto field number; "to max" reserves up
// to it.
const maxFieldNumber = 536870911

type numRange struct{ lo, hi int64 }

type fieldInfo struct {
	name       string
	number     int64
	deprecated bool
	atMinor    string
	disallowed bool
	hidden     bool
	file       string
}

type valueInfo struct {
	name       string
	deprecated bool
	atMinor    string
	hidden     bool
}

// symbol is a message or an enum.
type symbol struct {
	full        string
	isEnum      bool
	file        string
	deprecated  bool
	hidden      bool
	fields      map[string]*fieldInfo
	values      map[string]*valueInfo
	resNums     []numRange
	resNames    map[string]bool
	fieldNumber map[int64]string
}

type parsed struct {
	pkg   string
	syms  []*symbol
	items int
}

type parser struct {
	lx       *lexed
	pos      int
	file     string
	pkg      string
	out      *parsed
	maxNest  int
	maxItems int
}

type parseFault struct {
	line   int
	reason string
}

func (e *parseFault) Error() string { return fmt.Sprintf("line %d: %s", e.line, e.reason) }

func (p *parser) fail(reason string) error {
	line := 0
	if p.pos < len(p.lx.toks) {
		line = p.lx.toks[p.pos].line
	} else if len(p.lx.toks) > 0 {
		line = p.lx.toks[len(p.lx.toks)-1].line
	}
	return &parseFault{line: line, reason: reason}
}

func (p *parser) more() bool { return p.pos < len(p.lx.toks) }

func (p *parser) peek(k int) (token, bool) {
	if p.pos+k < len(p.lx.toks) {
		return p.lx.toks[p.pos+k], true
	}
	return token{}, false
}

func (p *parser) isPunct(k int, s string) bool {
	t, ok := p.peek(k)
	return ok && t.kind == tPunct && t.text == s
}

func (p *parser) isIdent(k int, s string) bool {
	t, ok := p.peek(k)
	return ok && t.kind == tIdent && t.text == s
}

func (p *parser) expectPunct(s string) error {
	if !p.isPunct(0, s) {
		return p.fail("expected " + s)
	}
	p.pos++
	return nil
}

func (p *parser) ident() (string, error) {
	t, ok := p.peek(0)
	if !ok || t.kind != tIdent || strings.ContainsRune(t.text, '.') || strings.HasPrefix(t.text, ".") {
		return "", p.fail("expected a simple name")
	}
	p.pos++
	return t.text, nil
}

// hidden reports whether the declaration whose first token is at line carries
// the hide marker in the comment-only lines directly above it.
func (p *parser) hiddenAt(line int) bool {
	for l := line - 1; l >= 1 && p.lx.commentOnly[l]; l-- {
		if p.lx.hide[l] {
			return true
		}
	}
	return false
}

// skipStatement skips to the ';' that ends a statement, balancing all
// brackets. The ';' is consumed.
func (p *parser) skipStatement() error {
	depth := 0
	for p.more() {
		t := p.lx.toks[p.pos]
		p.pos++
		if t.kind != tPunct {
			continue
		}
		switch t.text {
		case "{", "[", "(":
			depth++
		case "}", "]", ")":
			depth--
			if depth < 0 {
				return p.fail("unbalanced bracket")
			}
		case ";":
			if depth == 0 {
				return nil
			}
		}
	}
	return p.fail("unterminated statement")
}

// skipBlock skips "{ ... }" with balanced braces; the cursor is at '{'.
func (p *parser) skipBlock() error {
	if err := p.expectPunct("{"); err != nil {
		return err
	}
	depth := 1
	for p.more() {
		t := p.lx.toks[p.pos]
		p.pos++
		if t.kind == tPunct {
			switch t.text {
			case "{":
				depth++
			case "}":
				depth--
				if depth == 0 {
					return nil
				}
			}
		}
	}
	return p.fail("unterminated block")
}

func (p *parser) parseFile() error {
	for p.more() {
		t := p.lx.toks[p.pos]
		switch {
		case t.kind == tPunct && t.text == ";":
			p.pos++
		case t.kind != tIdent:
			return p.fail("unexpected token at top level")
		case t.text == "syntax" || t.text == "edition" || t.text == "import" || t.text == "option":
			if err := p.skipStatement(); err != nil {
				return err
			}
		case t.text == "package":
			p.pos++
			name, ok := p.peek(0)
			if !ok || name.kind != tIdent || strings.HasPrefix(name.text, ".") || p.pkg != "" {
				return p.fail("bad or repeated package")
			}
			p.pkg = name.text
			p.pos++
			if err := p.expectPunct(";"); err != nil {
				return err
			}
		case t.text == "message":
			if err := p.parseMessage(p.pkg, 1, false); err != nil {
				return err
			}
		case t.text == "enum":
			if err := p.parseEnum(p.pkg, false); err != nil {
				return err
			}
		case t.text == "service" || t.text == "extend":
			p.pos++
			for p.more() && !p.isPunct(0, "{") {
				p.pos++
			}
			if err := p.skipBlock(); err != nil {
				return err
			}
		default:
			return p.fail("unknown top-level statement")
		}
	}
	p.out.pkg = p.pkg
	return nil
}

func join(scope, name string) string {
	if scope == "" {
		return name
	}
	return scope + "." + name
}

func (p *parser) count() error {
	p.out.items++
	if p.out.items > p.maxItems {
		return p.fail("declaration limit")
	}
	return nil
}

func newSymbol(full string, enum bool, file string, hidden bool) *symbol {
	return &symbol{full: full, isEnum: enum, file: file, hidden: hidden,
		fields: map[string]*fieldInfo{}, values: map[string]*valueInfo{},
		resNames: map[string]bool{}, fieldNumber: map[int64]string{}}
}

// optionValue parses a "name = value" option from toks up to a terminator
// (',' or ']' for field options, ';' for statements) and returns the name
// tokens and value tokens. The cursor ends on the terminator.
func (p *parser) optionPair(term func(token) bool) (name, value []token, err error) {
	depth := 0
	inValue := false
	for p.more() {
		t := p.lx.toks[p.pos]
		if t.kind == tPunct {
			if depth == 0 && term(t) {
				return name, value, nil
			}
			switch t.text {
			case "{", "[", "(":
				depth++
			case "}", "]", ")":
				depth--
				if depth < 0 {
					return nil, nil, p.fail("unbalanced bracket")
				}
			case "=":
				if depth == 0 && !inValue {
					inValue = true
					p.pos++
					continue
				}
			}
		}
		if inValue {
			value = append(value, t)
		} else {
			name = append(name, t)
		}
		p.pos++
	}
	return nil, nil, p.fail("unterminated option")
}

// optionEffect interprets one option. It returns what the option says about
// deprecation; anything it does not recognise has no effect.
type optionEffect struct {
	deprecated bool
	atMinor    string
	disallowed bool
}

const (
	annDeprecatedAt     = "envoy.annotations.deprecated_at_minor_version"
	annDeprecatedAtEnum = "envoy.annotations.deprecated_at_minor_version_enum"
	annDisallowed       = "envoy.annotations.disallowed_by_default"
	annDisallowedEnum   = "envoy.annotations.disallowed_by_default_enum"
)

func (p *parser) interpret(name, value []token, enumValue bool) (optionEffect, error) {
	var eff optionEffect
	isBool := func() (bool, bool) {
		if len(value) == 1 && value[0].kind == tIdent {
			switch value[0].text {
			case "true":
				return true, true
			case "false":
				return false, true
			}
		}
		return false, false
	}
	switch {
	case len(name) == 1 && name[0].kind == tIdent && name[0].text == "deprecated":
		b, ok := isBool()
		if !ok {
			return eff, p.fail("deprecated option value is not true or false")
		}
		eff.deprecated = b
	case len(name) == 3 && name[0].text == "(" && name[2].text == ")" && name[1].kind == tIdent:
		ann := strings.TrimPrefix(name[1].text, ".")
		switch ann {
		case annDeprecatedAt, annDeprecatedAtEnum:
			if len(value) != 1 || value[0].kind != tString {
				return eff, p.fail("deprecated_at_minor_version is not a string")
			}
			v := value[0].text
			if v == "" || len(v) > 16 || strings.Trim(v, "0123456789.") != "" {
				return eff, p.fail("deprecated_at_minor_version has an unexpected form")
			}
			eff.atMinor = v
		case annDisallowed, annDisallowedEnum:
			b, ok := isBool()
			if !ok {
				return eff, p.fail("disallowed_by_default value is not true or false")
			}
			eff.disallowed = b
		}
	}
	return eff, nil
}

func (p *parser) parseNumber() (int64, error) {
	neg := false
	if p.isPunct(0, "-") {
		neg = true
		p.pos++
	}
	t, ok := p.peek(0)
	if !ok || t.kind != tNumber {
		return 0, p.fail("expected a number")
	}
	v, err := strconv.ParseInt(t.text, 0, 64)
	if err != nil || v > maxFieldNumber {
		return 0, p.fail("number out of range")
	}
	p.pos++
	if neg {
		v = -v
	}
	return v, nil
}

// bracketOptions parses "[ opt, opt ]" and folds the effects.
func (p *parser) bracketOptions(enumValue bool) (optionEffect, error) {
	var total optionEffect
	if err := p.expectPunct("["); err != nil {
		return total, err
	}
	for {
		name, value, err := p.optionPair(func(t token) bool { return t.text == "," || t.text == "]" })
		if err != nil {
			return total, err
		}
		if len(name) == 0 {
			return total, p.fail("empty option")
		}
		eff, err := p.interpret(name, value, enumValue)
		if err != nil {
			return total, err
		}
		total.deprecated = total.deprecated || eff.deprecated
		if eff.atMinor != "" {
			total.atMinor = eff.atMinor
		}
		total.disallowed = total.disallowed || eff.disallowed
		sep := p.lx.toks[p.pos].text
		p.pos++
		if sep == "]" {
			return total, nil
		}
	}
}

func (p *parser) parseReserved(s *symbol) error {
	p.pos++ // reserved
	first, ok := p.peek(0)
	if !ok {
		return p.fail("unterminated reserved")
	}
	if first.kind == tString || first.kind == tIdent {
		for {
			t, ok := p.peek(0)
			if !ok || (t.kind != tString && t.kind != tIdent) {
				return p.fail("bad reserved name")
			}
			p.pos++
			s.resNames[t.text] = true
			if p.isPunct(0, ",") {
				p.pos++
				continue
			}
			return p.expectPunct(";")
		}
	}
	for {
		lo, err := p.parseNumber()
		if err != nil {
			return err
		}
		hi := lo
		if p.isIdent(0, "to") {
			p.pos++
			if p.isIdent(0, "max") {
				p.pos++
				hi = maxFieldNumber
			} else if hi, err = p.parseNumber(); err != nil {
				return err
			}
		}
		if hi < lo {
			return p.fail("reserved range is reversed")
		}
		s.resNums = append(s.resNums, numRange{lo, hi})
		if p.isPunct(0, ",") {
			p.pos++
			continue
		}
		return p.expectPunct(";")
	}
}

func (p *parser) parseMessage(scope string, depth int, parentHidden bool) error {
	if depth > p.maxNest {
		return p.fail("message nesting limit")
	}
	start := p.lx.toks[p.pos]
	p.pos++ // message
	name, err := p.ident()
	if err != nil {
		return err
	}
	if err := p.count(); err != nil {
		return err
	}
	s := newSymbol(join(scope, name), false, p.file, parentHidden || p.hiddenAt(start.line))
	p.out.syms = append(p.out.syms, s)
	if err := p.expectPunct("{"); err != nil {
		return err
	}
	return p.messageBody(s, depth, false)
}

func (p *parser) messageBody(s *symbol, depth int, inOneof bool) error {
	for {
		t, ok := p.peek(0)
		if !ok {
			return p.fail("unterminated message")
		}
		if t.kind == tPunct {
			switch t.text {
			case "}":
				p.pos++
				return nil
			case ";":
				p.pos++
				continue
			}
			return p.fail("unexpected token in message")
		}
		if t.kind != tIdent {
			return p.fail("unexpected token in message")
		}
		// A keyword is a keyword only in its declaring shape; otherwise the
		// word is a type name and the statement is a field.
		block := p.isPunct(2, "{")
		switch {
		case t.text == "message" && block && !inOneof:
			if err := p.parseMessage(s.full, depth+1, s.hidden); err != nil {
				return err
			}
		case t.text == "enum" && block && !inOneof:
			if err := p.parseEnum(s.full, s.hidden); err != nil {
				return err
			}
		case t.text == "oneof" && block && !inOneof:
			p.pos += 3
			if err := p.messageBody(s, depth, true); err != nil {
				return err
			}
		case t.text == "extend" && !inOneof:
			p.pos++
			for p.more() && !p.isPunct(0, "{") {
				p.pos++
			}
			if err := p.skipBlock(); err != nil {
				return err
			}
		case t.text == "extensions":
			if err := p.skipStatement(); err != nil {
				return err
			}
		case t.text == "reserved" && !inOneof:
			if err := p.parseReserved(s); err != nil {
				return err
			}
		case t.text == "option":
			p.pos++
			name, value, err := p.optionPair(func(t token) bool { return t.text == ";" })
			if err != nil {
				return err
			}
			p.pos++ // ;
			eff, err := p.interpret(name, value, false)
			if err != nil {
				return err
			}
			if eff.deprecated && !inOneof {
				s.deprecated = true
			}
		case t.text == "group":
			return p.fail("proto2 groups are not supported")
		default:
			if err := p.parseField(s); err != nil {
				return err
			}
		}
	}
}

func (p *parser) parseField(s *symbol) error {
	start := p.lx.toks[p.pos]
	if t, _ := p.peek(0); t.kind == tIdent && (t.text == "optional" || t.text == "required" || t.text == "repeated") && !p.isPunct(1, "=") && !p.isPunct(2, "=") {
		p.pos++
	}
	// type
	t, ok := p.peek(0)
	if !ok || t.kind != tIdent {
		return p.fail("expected a field type")
	}
	if t.text == "group" {
		return p.fail("proto2 groups are not supported")
	}
	p.pos++
	if t.text == "map" && p.isPunct(0, "<") {
		p.pos++
		for i := 0; i < 3; i++ {
			want := []string{"", ",", ""}[i]
			if want == "" {
				if tt, ok := p.peek(0); !ok || tt.kind != tIdent {
					return p.fail("bad map type")
				}
				p.pos++
			} else if err := p.expectPunct(want); err != nil {
				return err
			}
		}
		if err := p.expectPunct(">"); err != nil {
			return err
		}
	}
	name, err := p.ident()
	if err != nil {
		return err
	}
	if err := p.expectPunct("="); err != nil {
		return err
	}
	num, err := p.parseNumber()
	if err != nil {
		return err
	}
	var eff optionEffect
	if p.isPunct(0, "[") {
		if eff, err = p.bracketOptions(false); err != nil {
			return err
		}
	}
	if err := p.expectPunct(";"); err != nil {
		return err
	}
	if err := p.count(); err != nil {
		return err
	}
	if _, dup := s.fields[name]; dup {
		return p.fail("duplicate field name")
	}
	if _, dup := s.fieldNumber[num]; dup {
		return p.fail("duplicate field number")
	}
	s.fields[name] = &fieldInfo{name: name, number: num, deprecated: eff.deprecated, atMinor: eff.atMinor,
		disallowed: eff.disallowed, hidden: s.hidden || p.hiddenAt(start.line), file: s.file}
	s.fieldNumber[num] = name
	return nil
}

func (p *parser) parseEnum(scope string, parentHidden bool) error {
	start := p.lx.toks[p.pos]
	p.pos++
	name, err := p.ident()
	if err != nil {
		return err
	}
	if err := p.count(); err != nil {
		return err
	}
	s := newSymbol(join(scope, name), true, p.file, parentHidden || p.hiddenAt(start.line))
	p.out.syms = append(p.out.syms, s)
	if err := p.expectPunct("{"); err != nil {
		return err
	}
	for {
		t, ok := p.peek(0)
		if !ok {
			return p.fail("unterminated enum")
		}
		if t.kind == tPunct {
			switch t.text {
			case "}":
				p.pos++
				return nil
			case ";":
				p.pos++
				continue
			}
			return p.fail("unexpected token in enum")
		}
		if t.kind != tIdent {
			return p.fail("unexpected token in enum")
		}
		switch {
		case t.text == "option":
			p.pos++
			n, v, err := p.optionPair(func(t token) bool { return t.text == ";" })
			if err != nil {
				return err
			}
			p.pos++
			eff, err := p.interpret(n, v, false)
			if err != nil {
				return err
			}
			if eff.deprecated {
				s.deprecated = true
			}
		case t.text == "reserved":
			if err := p.parseReserved(s); err != nil {
				return err
			}
		default:
			vname, err := p.ident()
			if err != nil {
				return err
			}
			if err := p.expectPunct("="); err != nil {
				return err
			}
			if _, err := p.parseNumber(); err != nil {
				return err
			}
			var eff optionEffect
			if p.isPunct(0, "[") {
				if eff, err = p.bracketOptions(true); err != nil {
					return err
				}
			}
			if err := p.expectPunct(";"); err != nil {
				return err
			}
			if err := p.count(); err != nil {
				return err
			}
			if _, dup := s.values[vname]; dup {
				return p.fail("duplicate enum value")
			}
			s.values[vname] = &valueInfo{name: vname, deprecated: eff.deprecated, atMinor: eff.atMinor, hidden: s.hidden || p.hiddenAt(t.line)}
		}
	}
}

// parseProto parses one file. Any construct the parser does not understand is
// an error: nothing in the file is then used.
func parseProto(file string, src []byte, maxNest, maxItems int) (*parsed, error) {
	lx, err := lex(src)
	if err != nil {
		return nil, err
	}
	p := &parser{lx: lx, file: file, out: &parsed{}, maxNest: maxNest, maxItems: maxItems}
	if err := p.parseFile(); err != nil {
		return nil, err
	}
	return p.out, nil
}
