package pathset

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strings"
	"unicode/utf8"
)

// Bounds. Input above either bound is refused, never truncated.
const (
	MaxPaths     = 10000
	MaxPathBytes = 4096
)

// Typed refusals; match with errors.Is.
var (
	ErrEmptySet     = errors.New("pathset: empty path set")
	ErrTooManyPaths = errors.New("pathset: too many paths")
	ErrEmptyPath    = errors.New("pathset: empty path")
	ErrNewline      = errors.New("pathset: path contains newline")
	ErrNUL          = errors.New("pathset: path contains NUL")
	ErrInvalidUTF8  = errors.New("pathset: path is not valid UTF-8")
	ErrPathTooLong  = errors.New("pathset: path too long")
	ErrDuplicate    = errors.New("pathset: duplicate path")
)

// Valid reports why paths cannot be digested, or nil. It does not modify or
// normalise the input.
func Valid(paths []string) error {
	if len(paths) == 0 {
		return ErrEmptySet
	}
	if len(paths) > MaxPaths {
		return ErrTooManyPaths
	}
	seen := make(map[string]struct{}, len(paths))
	for _, p := range paths {
		switch {
		case p == "":
			return ErrEmptyPath
		case len(p) > MaxPathBytes:
			return ErrPathTooLong
		case strings.IndexByte(p, '\n') >= 0:
			return ErrNewline
		case strings.IndexByte(p, 0) >= 0:
			return ErrNUL
		case !utf8.ValidString(p):
			return ErrInvalidUTF8
		}
		if _, dup := seen[p]; dup {
			return ErrDuplicate
		}
		seen[p] = struct{}{}
	}
	return nil
}

// Digest returns "sha256:<hex>" over the bytewise-sorted paths joined by "\n",
// or the Valid error. The input order never matters and is not modified.
func Digest(paths []string) (string, error) {
	if err := Valid(paths); err != nil {
		return "", err
	}
	sorted := append([]string(nil), paths...)
	sort.Strings(sorted)
	sum := sha256.Sum256([]byte(strings.Join(sorted, "\n")))
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
