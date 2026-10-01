// SPDX-License-Identifier: AGPL-3.0-only

package cncfprepare

import (
	"errors"
	"strings"
)

var errLexicalPythonSyntax = errors.New("Python source is outside the admitted lexical syntax")

// lexicalStringLiteralMarker cannot occur in admitted caller input: controls
// are rejected before scanning. It distinguishes a masked literal from every
// ASCII identifier the narrow source grammar can admit.
const lexicalStringLiteralMarker = "\x01"

type lexicalPythonLine struct {
	indent int
	text   string
}

// lexicalPythonLines removes comments and string contents before a deliberately
// closed Python source grammar is inspected. It retains indentation, rejects
// malformed delimiter nesting, and reports f-strings as dynamic rather than
// interpreting their embedded expressions. It is not a Python parser.
func lexicalPythonLines(source string) ([]lexicalPythonLine, bool, error) {
	for index := 0; index < len(source); index++ {
		value := source[index]
		if value < 0x20 && value != '\n' && value != '\r' && value != '\t' {
			return nil, false, errLexicalPythonSyntax
		}
	}
	physical := strings.Split(source, "\n")
	result := make([]lexicalPythonLine, len(physical))
	quote := byte(0)
	triple := false
	stack := make([]byte, 0, 16)
	dynamicString := false
	for index, line := range physical {
		indent := 0
		for indent < len(line) && line[indent] == ' ' {
			indent++
		}
		// Tabs are valid Python in some contexts, but their width depends on
		// surrounding layout. The admitted source subset is deliberately
		// spaces-only so lexical indentation cannot manufacture a top-level
		// binding from mixed-indentation source.
		if indent < len(line) && line[indent] == '\t' {
			return nil, false, errLexicalPythonSyntax
		}
		var out strings.Builder
		for cursor := 0; cursor < len(line); cursor++ {
			value := line[cursor]
			if quote != 0 {
				if value == '\\' {
					dynamicString = true
				}
				if triple && cursor+2 < len(line) && value == quote && line[cursor+1] == quote && line[cursor+2] == quote {
					out.WriteString(lexicalStringLiteralMarker + "  ")
					cursor += 2
					quote, triple = 0, false
					continue
				}
				out.WriteByte(' ')
				if !triple && value == quote && (cursor == 0 || line[cursor-1] != '\\') {
					quote = 0
				}
				continue
			}
			if value == '#' {
				out.WriteString(strings.Repeat(" ", len(line)-cursor))
				break
			}
			if value == '\'' || value == '"' {
				prefixStart := cursor
				for prefixStart > 0 && lexicalIdentifierByte(line[prefixStart-1]) {
					prefixStart--
				}
				if prefixStart != cursor {
					dynamicString = true
				}
				if cursor+2 < len(line) && line[cursor+1] == value && line[cursor+2] == value {
					quote, triple = value, true
					out.WriteString(lexicalStringLiteralMarker + "  ")
					cursor += 2
				} else {
					quote = value
					out.WriteString(lexicalStringLiteralMarker)
				}
				continue
			}
			out.WriteByte(value)
			switch value {
			case '(', '[', '{':
				stack = append(stack, value)
			case ')', ']', '}':
				if len(stack) == 0 || !lexicalMatchingDelimiter(stack[len(stack)-1], value) {
					return nil, false, errLexicalPythonSyntax
				}
				stack = stack[:len(stack)-1]
			}
		}
		if quote != 0 && !triple {
			return nil, false, errLexicalPythonSyntax
		}
		result[index] = lexicalPythonLine{indent: indent, text: strings.TrimSpace(out.String())}
	}
	if quote != 0 || len(stack) != 0 {
		return nil, false, errLexicalPythonSyntax
	}
	return result, dynamicString, nil
}

func lexicalMatchingDelimiter(open, close byte) bool {
	return open == '(' && close == ')' || open == '[' && close == ']' || open == '{' && close == '}'
}

func lexicalIdentifierByte(value byte) bool {
	return value == '_' || value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9'
}
