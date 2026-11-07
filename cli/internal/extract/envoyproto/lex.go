// SPDX-License-Identifier: AGPL-3.0-only

package envoyproto

import (
	"errors"
	"strings"
)

type tokKind uint8

const (
	tIdent tokKind = iota
	tNumber
	tString
	tPunct
)

type token struct {
	kind tokKind
	text string // for tString: the raw bytes between the quotes
	line int
}

// hideMarker is the leading-comment convention that keeps a declaration out of
// the published API documentation.
const hideMarker = "[#not-implemented-hide:"

// lexed is the token stream of one file plus the comment facts the parser
// needs: which lines are comment-only lines, and which of those carry the
// hide marker. Comments never produce tokens, so no word in a comment can
// reach an option check.
type lexed struct {
	toks        []token
	commentOnly map[int]bool
	hide        map[int]bool
	// blockLines are lines a block comment touches. They do not break the
	// run of comment lines above a declaration, and a hide marker inside a
	// block comment counts as a marker: a hidden declaration can never become
	// visible by a comment inserted between marker and declaration.
	blockLines map[int]bool
}

var errLex = errors.New("lexical error")

func isIdentStart(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_'
}
func isDigit(c byte) bool { return c >= '0' && c <= '9' }
func isIdentByte(c byte) bool {
	return isIdentStart(c) || isDigit(c)
}

// lex is a pure text tokenizer for the proto2/proto3 surface Envoy uses. It
// refuses (error) NUL bytes, bytes outside ASCII outside comments and
// strings, unterminated strings and unterminated block comments.
func lex(src []byte) (*lexed, error) {
	out := &lexed{commentOnly: map[int]bool{}, hide: map[int]bool{}, blockLines: map[int]bool{}}
	line := 1
	lastTokLine := 0
	i := 0
	n := len(src)
	for i < n {
		c := src[i]
		switch {
		case c == 0:
			return nil, errLex
		case c == '\n':
			line++
			i++
		case c == ' ' || c == '\t' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '/' && i+1 < n && src[i+1] == '/':
			j := i + 2
			for j < n && src[j] != '\n' {
				if src[j] == 0 {
					return nil, errLex
				}
				j++
			}
			if lastTokLine != line {
				out.commentOnly[line] = true
				if strings.HasPrefix(strings.TrimSpace(string(src[i+2:j])), hideMarker) {
					out.hide[line] = true
				}
			}
			i = j
		case c == '/' && i+1 < n && src[i+1] == '*':
			j := i + 2
			closed := false
			startLine := line
			for j+1 < n {
				if src[j] == 0 {
					return nil, errLex
				}
				if src[j] == '*' && src[j+1] == '/' {
					closed = true
					break
				}
				if src[j] == '\n' {
					line++
				}
				j++
			}
			if !closed {
				return nil, errLex
			}
			if strings.Contains(string(src[i:j]), hideMarker) {
				out.hide[startLine] = true
			}
			if lastTokLine != startLine {
				for k := startLine; k <= line; k++ {
					out.blockLines[k] = true
				}
			}
			i = j + 2
			lastTokLine = line
		case c == '"' || c == '\'':
			j := i + 1
			for {
				if j >= n || src[j] == '\n' || src[j] == 0 {
					return nil, errLex
				}
				if src[j] == '\\' {
					if j+1 >= n || src[j+1] == '\n' || src[j+1] == 0 {
						return nil, errLex
					}
					j += 2
					continue
				}
				if src[j] == c {
					break
				}
				j++
			}
			out.toks = append(out.toks, token{kind: tString, text: string(src[i+1 : j]), line: line})
			lastTokLine = line
			i = j + 1
		case isIdentStart(c) || c == '.' && i+1 < n && isIdentStart(src[i+1]):
			j := i + 1
			for j < n && (isIdentByte(src[j]) || src[j] == '.' && j+1 < n && isIdentStart(src[j+1])) {
				j++
			}
			out.toks = append(out.toks, token{kind: tIdent, text: string(src[i:j]), line: line})
			lastTokLine = line
			i = j
		case isDigit(c) || c == '.' && i+1 < n && isDigit(src[i+1]):
			j := i + 1
			for j < n && (isIdentByte(src[j]) || src[j] == '.') {
				j++
			}
			out.toks = append(out.toks, token{kind: tNumber, text: string(src[i:j]), line: line})
			lastTokLine = line
			i = j
		case strings.IndexByte("{}[]()<>=;,:-+/@", c) >= 0:
			out.toks = append(out.toks, token{kind: tPunct, text: string(c), line: line})
			lastTokLine = line
			i++
		default:
			return nil, errLex
		}
	}
	return out, nil
}
