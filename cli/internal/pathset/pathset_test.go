package pathset

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

type vector struct {
	Name   string   `json:"name"`
	Paths  []string `json:"paths"`
	Digest string   `json:"digest"`
	Error  string   `json:"error"`
}

var errClass = map[string]error{
	"empty-set":      ErrEmptySet,
	"too-many-paths": ErrTooManyPaths,
	"empty-path":     ErrEmptyPath,
	"newline":        ErrNewline,
	"nul":            ErrNUL,
	"invalid-utf8":   ErrInvalidUTF8,
	"path-too-long":  ErrPathTooLong,
	"duplicate":      ErrDuplicate,
}

func loadVectors(t *testing.T) []vector {
	t.Helper()
	b, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Version int      `json:"version"`
		Vectors []vector `json:"vectors"`
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		t.Fatal(err)
	}
	if f.Version != 1 || len(f.Vectors) < 15 {
		t.Fatalf("vectors file version %d, %d vectors", f.Version, len(f.Vectors))
	}
	return f.Vectors
}

func TestVectors(t *testing.T) {
	t.Parallel()
	valid, invalid := 0, 0
	for _, v := range loadVectors(t) {
		in := append([]string(nil), v.Paths...)
		got, err := Digest(v.Paths)
		verr := Valid(v.Paths)
		if !reflect.DeepEqual(in, v.Paths) {
			t.Fatalf("%s: input modified", v.Name)
		}
		if v.Error != "" {
			want, ok := errClass[v.Error]
			if !ok || v.Digest != "" {
				t.Fatalf("%s: bad vector", v.Name)
			}
			if !errors.Is(err, want) || !errors.Is(verr, want) || got != "" {
				t.Errorf("%s: got %q %v / %v, want %v", v.Name, got, err, verr, want)
			}
			invalid++
			continue
		}
		if err != nil || verr != nil || got != v.Digest {
			t.Errorf("%s: got %q %v / %v, want %s", v.Name, got, err, verr, v.Digest)
		}
		valid++
	}
	if valid < 10 || invalid < 6 {
		t.Fatalf("too few vectors: %d valid, %d invalid", valid, invalid)
	}
}

// Independent computation for the pinned a/x + b/y case and the vectors that
// were fixed by the first producer of this digest.
func TestKnownDigests(t *testing.T) {
	t.Parallel()
	sum := sha256.Sum256([]byte("a/x\nb/y"))
	want := "sha256:" + hex.EncodeToString(sum[:])
	for _, in := range [][]string{{"b/y", "a/x"}, {"a/x", "b/y"}} {
		if got, err := Digest(in); err != nil || got != want {
			t.Fatalf("%v: %s %v want %s", in, got, err, want)
		}
	}
	pins := map[string][]string{
		"sha256:d2212e911b2cb1907429cd8aaa46108fac5a1a45833937a40a610d431d343c94": {"cli/old/a.json", "cli/new/a.json"},
		"sha256:8330e54fb1d88876b73e7ed121281cb339e4c9680a69a8507bd137fc4a8ee41d": {"cli/new/a.json", "cli/old/a.json", "cli/x.json"},
		"sha256:86f5689f8a50b4e97590e495881dc48c3c972f868affdf0802afb5559fb5c165": {"cli/gone.json"},
	}
	for d, in := range pins {
		if got, err := Digest(in); err != nil || got != d {
			t.Fatalf("%v: %s %v want %s", in, got, err, d)
		}
	}
}

// Bytewise UTF-8, not UTF-16 or locale: U+FF5E (EF BD 9E) sorts before
// U+10000 (F0 90 80 80); 'z' sorts before e-acute (C3 A9).
func TestSortIsBytewiseUTF8(t *testing.T) {
	t.Parallel()
	for _, c := range []struct{ a, b string }{{"～", "\U00010000"}, {"z", "é"}, {"B", "a"}} {
		sum := sha256.Sum256([]byte(c.a + "\n" + c.b))
		want := "sha256:" + hex.EncodeToString(sum[:])
		for _, in := range [][]string{{c.a, c.b}, {c.b, c.a}} {
			if got, err := Digest(in); err != nil || got != want {
				t.Fatalf("%q: %s %v want %s", in, got, err, want)
			}
		}
	}
}

func TestSeparatorAndNoCollision(t *testing.T) {
	t.Parallel()
	a, _ := Digest([]string{"a", "b"})
	b, _ := Digest([]string{"a,b"})
	c, _ := Digest([]string{"ab"})
	if a == b || a == c || b == c {
		t.Fatal("distinct sets collide")
	}
	if _, err := Digest([]string{"a\nb"}); !errors.Is(err, ErrNewline) {
		t.Fatalf("newline path: %v", err)
	}
	// Half a rename is a different change.
	r, _ := Digest([]string{"o", "n"})
	h, _ := Digest([]string{"o"})
	if r == h {
		t.Fatal("rename digests like a half")
	}
}

func TestNoNormalisation(t *testing.T) {
	t.Parallel()
	for _, p := range [][2]string{{"a/b", "a/b/"}, {"a/b", "a//b"}, {"a/b", "a/./b"}, {"A/x", "a/x"}, {"a/b", "./a/b"}} {
		d1, e1 := Digest([]string{p[0]})
		d2, e2 := Digest([]string{p[1]})
		if e1 != nil || e2 != nil || d1 == d2 {
			t.Fatalf("%q and %q were normalised or refused: %v %v", p[0], p[1], e1, e2)
		}
	}
	// Both spellings may sit in one set: no hidden dedupe by cleaning.
	if err := Valid([]string{"a/b", "a/b/", "A/b"}); err != nil {
		t.Fatal(err)
	}
}

func TestInvalidInputs(t *testing.T) {
	t.Parallel()
	long := strings.Repeat("a", MaxPathBytes)
	many := make([]string, MaxPaths)
	for i := range many {
		many[i] = "p" + strconv.Itoa(i)
	}
	cases := []struct {
		name  string
		paths []string
		want  error
	}{
		{"nil", nil, ErrEmptySet},
		{"empty slice", []string{}, ErrEmptySet},
		{"empty path", []string{""}, ErrEmptyPath},
		{"nul", []string{"a\x00"}, ErrNUL},
		{"nul alone", []string{"\x00"}, ErrNUL},
		{"newline at end", []string{"a\n"}, ErrNewline},
		{"invalid utf8", []string{"a\xffb"}, ErrInvalidUTF8},
		{"duplicate adjacent", []string{"a", "a"}, ErrDuplicate},
		{"duplicate far", []string{"a", "b", "c", "a"}, ErrDuplicate},
		{"too long", []string{long + "a"}, ErrPathTooLong},
		{"too many", append(append([]string(nil), many...), "extra"), ErrTooManyPaths},
	}
	for _, c := range cases {
		if d, err := Digest(c.paths); !errors.Is(err, c.want) || d != "" {
			t.Errorf("%s: Digest %q %v want %v", c.name, d, err, c.want)
		}
		if err := Valid(c.paths); !errors.Is(err, c.want) {
			t.Errorf("%s: Valid %v want %v", c.name, err, c.want)
		}
	}
	// Boundaries are accepted.
	if err := Valid([]string{long}); err != nil {
		t.Errorf("max length path refused: %v", err)
	}
	if err := Valid(many); err != nil {
		t.Errorf("max count refused: %v", err)
	}
	// A carriage return is an ordinary byte here (no normalisation).
	if err := Valid([]string{"a\rb"}); err != nil {
		t.Errorf("CR refused: %v", err)
	}
}

func TestInputNotModified(t *testing.T) {
	t.Parallel()
	in := []string{"c", "a", "b"}
	if _, err := Digest(in); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(in, []string{"c", "a", "b"}) {
		t.Fatalf("input reordered: %v", in)
	}
}

// Leaf: standard library only.
func TestLeafImports(t *testing.T) {
	t.Parallel()
	for _, f := range []string{"pathset.go", "doc.go"} {
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if strings.Contains(strings.SplitN(p, "/", 2)[0], ".") {
				t.Errorf("%s imports non-stdlib %s", f, p)
			}
		}
	}
}
