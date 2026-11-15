// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"context"
	"strings"
	"testing"
	"time"
)

// fakeRunner returns canned results in order (the last one repeats) and
// records every call. No test here touches the network.
type fakeRunner struct {
	results []ExecResult
	calls   []ExecSpec
	ctxs    []context.Context
}

func (f *fakeRunner) Run(ctx context.Context, spec ExecSpec) ExecResult {
	f.calls = append(f.calls, spec)
	f.ctxs = append(f.ctxs, ctx)
	i := len(f.calls) - 1
	if i >= len(f.results) {
		i = len(f.results) - 1
	}
	return f.results[i]
}

func okRun(out string) ExecResult { return ExecResult{Stdout: []byte(out)} }
func errRun(exit int, stderr string) ExecResult {
	return ExecResult{Exit: exit, Stderr: []byte(stderr)}
}

const bHead = "1111111111111111111111111111111111111111"

func hx(c byte) string { return strings.Repeat(string(c), 40) }

// bTags is a three-tag window; commits a, b, c.
func bRecipe() *Recipe {
	r := &Recipe{Repo: "github.com/example/demo"}
	for i, t := range []string{"v1.0.0", "v1.1.0", "v1.2.0"} {
		r.Commits = append(r.Commits, recipeCommit{Tag: t, Commit: hx("abc"[i])})
	}
	return r
}

func bBundle(r *Recipe) func(string) (string, bool) {
	return func(tag string) (string, bool) {
		for _, c := range r.Commits {
			if c.Tag == tag {
				return c.Commit, true
			}
		}
		return "", false
	}
}

// lsOut builds ls-remote output. kinds: "l" lightweight, "a" annotated.
func lsOut(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

func goodOut() string {
	return lsOut(
		hx('a')+"\trefs/tags/v1.0.0",
		hx('f')+"\trefs/tags/v1.1.0", // annotated: tag object
		hx('b')+"\trefs/tags/v1.1.0^{}",
		hx('c')+"\trefs/tags/v1.2.0",
	)
}

func bind(r *Recipe, run *fakeRunner) (*BindingResult, *VerifyFailure, []time.Duration) {
	var sleeps []time.Duration
	res, f := Binder{Runner: run, Sleep: func(d time.Duration) { sleeps = append(sleeps, d) }}.Bind(r, bBundle(r), bHead)
	return res, f, sleeps
}

func wantBind(t *testing.T, out string, code string, harnessClass bool) *fakeRunner {
	t.Helper()
	run := &fakeRunner{results: []ExecResult{okRun(out)}}
	res, f, _ := bind(bRecipe(), run)
	if f == nil {
		t.Fatalf("accepted (want %s): %+v", code, res)
	}
	if f.Code != code || f.Harness != harnessClass {
		t.Fatalf("got %s harness=%v (%s), want %s harness=%v", f.Code, f.Harness, f.Detail, code, harnessClass)
	}
	if res != nil {
		t.Fatal("a failure must carry no result")
	}
	return run
}

func TestBindingAcceptsLightweightAnnotatedAndMixed(t *testing.T) {
	run := &fakeRunner{results: []ExecResult{okRun(goodOut())}}
	res, f, _ := bind(bRecipe(), run)
	if f != nil {
		t.Fatal(f)
	}
	if len(res.Tags) != 3 || res.Annotated != 1 || res.Lightweight != 2 || res.HeadSHA != bHead || res.Repo != "github.com/example/demo" {
		t.Fatalf("%+v", res)
	}
	if !res.Tags[1].Annotated || res.Tags[1].Commit != hx('b') || res.Tags[0].Annotated {
		t.Fatalf("peeled commit must be the compared value: %+v", res.Tags)
	}
	if len(run.calls) != 1 {
		t.Fatal("one call")
	}
	// All lightweight.
	run = &fakeRunner{results: []ExecResult{okRun(lsOut(hx('a')+"\trefs/tags/v1.0.0", hx('b')+"\trefs/tags/v1.1.0", hx('c')+"\trefs/tags/v1.2.0"))}}
	if res, f, _ := bind(bRecipe(), run); f != nil || res.Annotated != 0 || res.Lightweight != 3 {
		t.Fatalf("%v %+v", f, res)
	}
	// All annotated.
	run = &fakeRunner{results: []ExecResult{okRun(lsOut(
		hx('1')+"\trefs/tags/v1.0.0", hx('a')+"\trefs/tags/v1.0.0^{}",
		hx('2')+"\trefs/tags/v1.1.0", hx('b')+"\trefs/tags/v1.1.0^{}",
		hx('3')+"\trefs/tags/v1.2.0", hx('c')+"\trefs/tags/v1.2.0^{}"))}}
	if res, f, _ := bind(bRecipe(), run); f != nil || res.Annotated != 3 {
		t.Fatalf("%v %+v", f, res)
	}
	// Line order from the server does not matter.
	run = &fakeRunner{results: []ExecResult{okRun(lsOut(hx('c')+"\trefs/tags/v1.2.0", hx('b')+"\trefs/tags/v1.1.0^{}", hx('f')+"\trefs/tags/v1.1.0", hx('a')+"\trefs/tags/v1.0.0"))}}
	res2, f, _ := bind(bRecipe(), run)
	if f != nil {
		t.Fatal(f)
	}
	if res2.Digest != res.Digest {
		t.Fatal("the digest must not depend on the server's line order")
	}
}

func TestBindingMismatchEveryPositionAndPeelMutant(t *testing.T) {
	// Commit differs on the first, a middle and the last tag.
	for _, victim := range []string{"v1.0.0", "v1.1.0", "v1.2.0"} {
		var lines []string
		for _, ln := range strings.Split(strings.TrimSpace(goodOut()), "\n") {
			sha, ref, _ := strings.Cut(ln, "\t")
			if ref == "refs/tags/"+victim || ref == "refs/tags/"+victim+"^{}" {
				sha = hx('9')
			}
			lines = append(lines, sha+"\t"+ref)
		}
		wantBind(t, lsOut(lines...), "binding-mismatch", false)
	}
	// Peeled differs while the ref line equals the recipe commit: a verifier
	// that ignores the peel would accept this.
	wantBind(t, lsOut(
		hx('a')+"\trefs/tags/v1.0.0",
		hx('b')+"\trefs/tags/v1.1.0", hx('9')+"\trefs/tags/v1.1.0^{}",
		hx('c')+"\trefs/tags/v1.2.0"), "binding-mismatch", false)
	// Annotated tag answered with only the tag object id (no peeled line):
	// the tag-object id is not the commit.
	wantBind(t, lsOut(
		hx('a')+"\trefs/tags/v1.0.0",
		hx('e')+"\trefs/tags/v1.1.0",
		hx('c')+"\trefs/tags/v1.2.0"), "binding-mismatch", false)
}

func TestBindingMalformedAnswersFailClosed(t *testing.T) {
	good := goodOut()
	for name, out := range map[string]string{
		"empty":              "",
		"only newline":       "\n",
		"truncated":          strings.TrimSuffix(good, "\n"),
		"cut mid line":       good[:len(good)-20],
		"extra ref":          good + hx('d') + "\trefs/tags/v9.9.9\n",
		"extra head ref":     good + hx('d') + "\tHEAD\n",
		"extra branch":       good + hx('d') + "\trefs/heads/main\n",
		"duplicate line":     lsOut(hx('a')+"\trefs/tags/v1.0.0", hx('a')+"\trefs/tags/v1.0.0", hx('b')+"\trefs/tags/v1.1.0", hx('c')+"\trefs/tags/v1.2.0"),
		"peeled alone":       lsOut(hx('a')+"\trefs/tags/v1.0.0", hx('b')+"\trefs/tags/v1.1.0^{}", hx('c')+"\trefs/tags/v1.2.0", hx('c')+"\trefs/tags/v1.2.0^{}"),
		"uppercase sha":      strings.Replace(good, hx('a'), strings.Repeat("A", 40), 1),
		"short sha":          strings.Replace(good, hx('a'), strings.Repeat("a", 39), 1),
		"space not tab":      strings.Replace(good, "\trefs/tags/v1.0.0", " refs/tags/v1.0.0", 1),
		"carriage return":    strings.Replace(good, "\n", "\r\n", 1),
		"stray text":         "warning: something\n" + good,
		"blank line":         "\n" + good,
		"nested tag name":    lsOut(hx('a')+"\trefs/tags/v1.0.0/x", hx('b')+"\trefs/tags/v1.1.0", hx('c')+"\trefs/tags/v1.2.0"),
		"too many lines":     strings.Repeat(hx('a')+"\trefs/tags/v1.0.0\n", 7),
		"oversize":           strings.Repeat("x", bindingMaxOutput+1),
		"other tag only":     lsOut(hx('d') + "\trefs/tags/v7.0.0"),
		"case variant tag":   lsOut(hx('a')+"\trefs/tags/V1.0.0", hx('b')+"\trefs/tags/v1.1.0", hx('c')+"\trefs/tags/v1.2.0"),
		"tag with prefix":    lsOut(hx('a')+"\trefs/tags/xv1.0.0", hx('b')+"\trefs/tags/v1.1.0", hx('c')+"\trefs/tags/v1.2.0"),
		"tag with suffix":    lsOut(hx('a')+"\trefs/tags/v1.0.0x", hx('b')+"\trefs/tags/v1.1.0", hx('c')+"\trefs/tags/v1.2.0"),
		"nul byte":           strings.Replace(good, "v1.0.0", "v1\x00.0.0", 1),
		"peeled before only": lsOut(hx('a')+"\trefs/tags/v1.0.0^{}", hx('b')+"\trefs/tags/v1.1.0", hx('c')+"\trefs/tags/v1.2.0"),
	} {
		t.Run(name, func(t *testing.T) {
			run := &fakeRunner{results: []ExecResult{okRun(out)}}
			if res, f, _ := bind(bRecipe(), run); f == nil || res != nil {
				t.Fatalf("accepted: %+v", res)
			} else if f.Harness {
				t.Fatalf("a bad answer is an assertion failure, got harness %v", f)
			}
		})
	}
	// Missing tag: first, middle, last.
	for _, victim := range []string{"v1.0.0", "v1.1.0", "v1.2.0"} {
		var lines []string
		for _, ln := range strings.Split(strings.TrimSpace(good), "\n") {
			if !strings.Contains(ln, "refs/tags/"+victim) {
				lines = append(lines, ln)
			}
		}
		wantBind(t, lsOut(lines...), "binding-missing", false)
	}
	// A 64-hex repository is refused with its own code.
	wantBind(t, lsOut(strings.Repeat("a", 64)+"\trefs/tags/v1.0.0", hx('b')+"\trefs/tags/v1.1.0", hx('c')+"\trefs/tags/v1.2.0"), "binding-hashalgo", false)
}

func TestBindingRunClassesAndAttempts(t *testing.T) {
	type tc struct {
		name     string
		results  []ExecResult
		code     string
		harness  bool
		attempts int
		sleeps   []time.Duration
	}
	back := []time.Duration{5 * time.Second, 15 * time.Second}
	good := okRun(goodOut())
	for _, c := range []tc{
		{"429 exhausts", []ExecResult{errRun(128, "fatal: unable to access 'x': The requested URL returned error: 429")}, "binding-unavailable", true, 3, back},
		{"503 exhausts", []ExecResult{errRun(128, "fatal: unable to access 'x': The requested URL returned error: 503")}, "binding-unavailable", true, 3, back},
		{"timeout flag exhausts", []ExecResult{{TimedOut: true, Stdout: []byte(goodOut())}}, "binding-unavailable", true, 3, back},
		{"connection reset exhausts", []ExecResult{errRun(128, "fatal: unable to access: Connection reset by peer")}, "binding-unavailable", true, 3, back},
		{"dns exhausts", []ExecResult{errRun(128, "fatal: unable to access: Could not resolve host: github.com")}, "binding-unavailable", true, 3, back},
		{"partial stdout with failure", []ExecResult{{Exit: 128, Stdout: []byte(goodOut()), Stderr: []byte("fatal: the remote end hung up unexpectedly")}}, "binding-unavailable", true, 3, back},
		{"partial stdout exit 1 not retried", []ExecResult{{Exit: 1, Stdout: []byte(goodOut())}}, "binding-unavailable", true, 1, nil},
		{"tls not retried", []ExecResult{errRun(128, "fatal: unable to access: SSL certificate problem")}, "binding-unavailable", true, 1, nil},
		{"redirect not retried", []ExecResult{errRun(128, "fatal: unable to update url base from redirection")}, "binding-redirect", false, 1, nil},
		{"301 not retried", []ExecResult{errRun(128, "fatal: unable to access: The requested URL returned error: 301")}, "binding-redirect", false, 1, nil},
		{"404 not retried", []ExecResult{errRun(128, "fatal: unable to access: The requested URL returned error: 404")}, "binding-unavailable", false, 1, nil},
		{"401 not retried", []ExecResult{errRun(128, "fatal: could not read Username for 'https://github.com': terminal prompts disabled")}, "binding-unavailable", false, 1, nil},
		{"403 not retried", []ExecResult{errRun(128, "fatal: unable to access: The requested URL returned error: 403")}, "binding-unavailable", false, 1, nil},
		{"unknown failure not retried", []ExecResult{errRun(2, "something odd")}, "binding-unavailable", true, 1, nil},
		{"git cannot run", []ExecResult{{Err: context.Canceled}}, "binding-unavailable", true, 1, nil},
		{"transient then ok-looking failure", []ExecResult{errRun(128, "returned error: 502"), errRun(128, "returned error: 404")}, "binding-unavailable", false, 2, back[:1]},
		{"transient then empty", []ExecResult{errRun(128, "returned error: 502"), okRun("")}, "binding-malformed", false, 2, back[:1]},
		{"transient then mismatch", []ExecResult{errRun(128, "returned error: 502"), okRun(strings.Replace(goodOut(), hx('c'), hx('9'), 1))}, "binding-mismatch", false, 2, back[:1]},
	} {
		t.Run(c.name, func(t *testing.T) {
			run := &fakeRunner{results: c.results}
			res, f, sleeps := bind(bRecipe(), run)
			if f == nil || res != nil {
				t.Fatalf("accepted %+v", res)
			}
			if f.Code != c.code || f.Harness != c.harness {
				t.Fatalf("%s harness=%v (%s), want %s harness=%v", f.Code, f.Harness, f.Detail, c.code, c.harness)
			}
			if len(run.calls) != c.attempts {
				t.Fatalf("%d attempts, want %d", len(run.calls), c.attempts)
			}
			if len(sleeps) != len(c.sleeps) {
				t.Fatalf("sleeps %v, want %v", sleeps, c.sleeps)
			}
			for i := range sleeps {
				if sleeps[i] != c.sleeps[i] {
					t.Fatalf("sleeps %v, want %v", sleeps, c.sleeps)
				}
			}
		})
	}
	// A transient failure followed by a good answer is accepted (retry works).
	run := &fakeRunner{results: []ExecResult{errRun(128, "returned error: 503"), good}}
	if res, f, _ := bind(bRecipe(), run); f != nil || len(res.Tags) != 3 || len(run.calls) != 2 {
		t.Fatalf("%v %d", f, len(run.calls))
	}
	// Every attempt carries the 60 s deadline.
	for _, c := range run.ctxs {
		dl, ok := c.Deadline()
		if !ok || time.Until(dl) > bindingTimeout || time.Until(dl) < bindingTimeout-5*time.Second {
			t.Fatal("the deadline must be 60 seconds")
		}
	}
	// No runner: never a pass.
	if _, f := (Binder{}).Bind(bRecipe(), bBundle(bRecipe()), bHead); f == nil || !f.Harness {
		t.Fatal("no runner is a harness failure")
	}
}

func TestBindingRejectsBadInputBeforeAnyExec(t *testing.T) {
	for name, repo := range map[string]string{
		"other host":       "gitlab.com/a/b",
		"suffix host":      "github.com.evil/a/b",
		"upper host":       "GitHub.com/a/b",
		"userinfo":         "github.com/a@b/c",
		"port":             "github.com/a/b:80",
		"colon":            "github.com:443/a/b",
		"dot dot":          "github.com/../x",
		"dots in name":     "github.com/a/b..c",
		"percent":          "github.com/a/b%2f",
		"dot git":          "github.com/a/b.git",
		"trailing dot":     "github.com/a/b.",
		"extra segment":    "github.com/a/b/c",
		"scheme":           "https://github.com/a/b",
		"empty":            "",
		"space":            "github.com/a/b c",
		"newline":          "github.com/a/b\n",
		"dash start owner": "github.com/-a/b",
		"query":            "github.com/a/b?x=1",
	} {
		t.Run("repo "+name, func(t *testing.T) {
			r := bRecipe()
			r.Repo = repo
			run := &fakeRunner{results: []ExecResult{okRun(goodOut())}}
			if _, f, _ := bind(r, run); f == nil || f.Code != "binding-input" {
				t.Fatalf("%v", f)
			}
			if len(run.calls) != 0 {
				t.Fatal("nothing may be executed for a refused repo")
			}
		})
	}
	for name, tag := range map[string]string{
		"star":         "v1.*",
		"question":     "v1.?",
		"bracket":      "v1.[0]",
		"leading dash": "-v1",
		"peel suffix":  "v1.0.0^{}",
		"caret":        "v1^",
		"backslash":    `v1\x`,
		"dot dot":      "v1..0",
		"slash":        "a/b",
		"space":        "v 1",
		"too long":     "v" + strings.Repeat("1", 100),
		"empty":        "",
		"colon":        "v1:2",
		"tilde":        "v1~1",
	} {
		t.Run("tag "+name, func(t *testing.T) {
			r := bRecipe()
			r.Commits[0].Tag = tag
			run := &fakeRunner{results: []ExecResult{okRun(goodOut())}}
			if _, f, _ := bind(r, run); f == nil || f.Code != "binding-input" {
				t.Fatalf("%v", f)
			}
			if len(run.calls) != 0 {
				t.Fatal("nothing may be executed for a refused tag")
			}
		})
	}
	// Recipe and bundle disagree on a commit; duplicate tag; bad commit; empty
	// and oversize windows; bad head sha.
	r := bRecipe()
	run := &fakeRunner{results: []ExecResult{okRun(goodOut())}}
	if _, f := (Binder{Runner: run}).Bind(r, func(string) (string, bool) { return hx('0'), true }, bHead); f == nil || f.Code != "binding-input" || len(run.calls) != 0 {
		t.Fatalf("%v", f)
	}
	if _, f := (Binder{Runner: run}).Bind(r, func(string) (string, bool) { return "", false }, bHead); f == nil || f.Code != "binding-input" || len(run.calls) != 0 {
		t.Fatalf("%v", f)
	}
	r = bRecipe()
	r.Commits[1].Tag = r.Commits[0].Tag
	if _, f, _ := bind(r, run); f == nil || f.Code != "binding-input" {
		t.Fatalf("%v", f)
	}
	r = bRecipe()
	r.Commits[0].Commit = strings.Repeat("A", 40)
	if _, f, _ := bind(r, run); f == nil || f.Code != "binding-input" {
		t.Fatalf("%v", f)
	}
	r = bRecipe()
	r.Commits = nil
	if _, f, _ := bind(r, run); f == nil || f.Code != "binding-input" {
		t.Fatalf("%v", f)
	}
	r = bRecipe()
	for i := 0; i <= MaxBundleTags; i++ {
		r.Commits = append(r.Commits, recipeCommit{Tag: "x" + strings.Repeat("a", i), Commit: hx('d')})
	}
	if _, f, _ := bind(r, run); f == nil || f.Code != "binding-input" {
		t.Fatalf("%v", f)
	}
	for _, bad := range []string{"", "abc", strings.Repeat("A", 40), strings.Repeat("1", 64)} {
		if _, f := (Binder{Runner: run}).Bind(bRecipe(), bBundle(bRecipe()), bad); f == nil || f.Code != "binding-input" {
			t.Fatalf("head %q: %v", bad, f)
		}
	}
	if len(run.calls) != 0 {
		t.Fatal("no exec for any refused input")
	}
}

func TestBindingArgvAndEnvAreFixed(t *testing.T) {
	run := &fakeRunner{results: []ExecResult{okRun(goodOut())}}
	r := bRecipe()
	// Listed out of order on purpose: the argv is sorted by tag.
	r.Commits[0], r.Commits[2] = r.Commits[2], r.Commits[0]
	if _, f, _ := bind(r, run); f != nil {
		t.Fatal(f)
	}
	want := []string{"git",
		"-c", "protocol.version=2", "-c", "http.followRedirects=false", "-c", "credential.helper=",
		"-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=20", "-c", "core.askPass=",
		"ls-remote", "--tags", "--", "https://github.com/example/demo.git",
		"refs/tags/v1.0.0", "refs/tags/v1.0.0^{}", "refs/tags/v1.1.0", "refs/tags/v1.1.0^{}", "refs/tags/v1.2.0", "refs/tags/v1.2.0^{}"}
	got := run.calls[0].Argv
	if len(got) != len(want) {
		t.Fatalf("%q", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("argv[%d] = %q, want %q", i, got[i], want[i])
		}
	}
	wantEnv := []string{"PATH=/usr/bin:/bin", "LC_ALL=C", "GIT_TERMINAL_PROMPT=0", "GIT_ALLOW_PROTOCOL=https",
		"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null", "GIT_CONFIG_NOSYSTEM=1", "GIT_ASKPASS=/bin/false"}
	env := run.calls[0].Env
	if len(env) != len(wantEnv) {
		t.Fatalf("%q", env)
	}
	for i := range wantEnv {
		if env[i] != wantEnv[i] {
			t.Fatalf("env[%d] = %q", i, env[i])
		}
		for _, bad := range []string{"TOKEN", "PROXY", "SSH", "HOME", "GITHUB", "http_proxy"} {
			if strings.Contains(strings.ToUpper(env[i]), bad) {
				t.Fatalf("env %q must not carry %s", env[i], bad)
			}
		}
	}
	// The real runner adds exactly HOME to the spec environment.
	re := runnerEnv(run.calls[0], "/tmp/h")
	if len(re) != len(wantEnv)+1 || re[len(re)-1] != "HOME=/tmp/h" {
		t.Fatalf("%q", re)
	}
	// The argument vector holds no shell: no element starts a command string.
	for _, a := range got[1:] {
		if strings.ContainsAny(a, " \t\n;|&$`") {
			t.Fatalf("argv element %q looks like shell text", a)
		}
	}
}

func TestExecRunnerRefusesAnythingButGit(t *testing.T) {
	for _, argv := range [][]string{nil, {"git"}, {"sh", "-c", "true"}, {"/usr/bin/git", "ls-remote"}} {
		if res := (execRunner{}).Run(context.Background(), ExecSpec{Argv: argv}); res.Err == nil {
			t.Fatalf("%q must be refused", argv)
		}
	}
}

func TestCappedBufferNeverReadsAsShort(t *testing.T) {
	c := &cappedBuffer{limit: 10}
	c.Write([]byte("0123456789"))
	if c.over || c.buf.Len() != 10 {
		t.Fatal("exactly the limit is not over")
	}
	c.Write([]byte("abcdef"))
	if !c.over || c.buf.Len() != 11 {
		t.Fatalf("over the limit keeps limit+1 bytes: %d", c.buf.Len())
	}
}

func TestBindingDigestIsStableAndSensitive(t *testing.T) {
	res, f, _ := bind(bRecipe(), &fakeRunner{results: []ExecResult{okRun(goodOut())}})
	if f != nil {
		t.Fatal(f)
	}
	again, _, _ := bind(bRecipe(), &fakeRunner{results: []ExecResult{okRun(goodOut())}})
	if res.Digest != again.Digest || len(res.Digest) != 64 {
		t.Fatal("not deterministic")
	}
	rev := []BindingTag{res.Tags[2], res.Tags[0], res.Tags[1]}
	if bindingDigest(res.Repo, rev) != res.Digest {
		t.Fatal("the digest must not depend on the order")
	}
	if bindingDigest("github.com/example/other", res.Tags) == res.Digest {
		t.Fatal("repo must be bound")
	}
	changed := append([]BindingTag(nil), res.Tags...)
	changed[0].Commit = hx('9')
	if bindingDigest(res.Repo, changed) == res.Digest {
		t.Fatal("commits must be bound")
	}
	if bindingDigest(res.Repo, res.Tags[:2]) == res.Digest {
		t.Fatal("the tag set must be bound")
	}
}
