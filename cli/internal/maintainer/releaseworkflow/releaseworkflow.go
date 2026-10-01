// SPDX-License-Identifier: AGPL-3.0-only

// Package releaseworkflow implements the local Community release workflow.
//
// It deliberately grants no publication authority. It operates only on a clean,
// caller-selected checkout and writes release candidates outside that checkout.
package releaseworkflow

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/releasegate"
	"github.com/prufyx/prufyx/cli/internal/maintainer/releasehelpers"
	"github.com/prufyx/prufyx/cli/internal/maintainer/releasesign"
)

const (
	requiredGo     = "go1.26.8"
	modulePath     = "github.com/prufyx/prufyx/cli"
	entrypoint     = "./cmd/prufyx-community"
	policyRel      = "cli/release/community-shipping-policy-v2.json"
	commandTimeout = 10 * time.Minute
)

func Run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "test":
		if len(args) != 1 {
			return usage()
		}
		return test(stdout, stderr)
	case "binary":
		if len(args) != 4 {
			return usage()
		}
		p, err := binary(args[1], args[2], args[3])
		if err == nil {
			_, err = fmt.Fprintln(stdout, p)
		}
		return err
	case "smoke":
		if len(args) != 4 {
			return usage()
		}
		return smoke(args[1], args[2], args[3], stdout)
	case "source":
		if len(args) != 3 {
			return usage()
		}
		p, err := source(args[1], args[2])
		if err == nil {
			_, err = fmt.Fprintln(stdout, p)
		}
		return err
	case "finalize":
		if len(args) != 3 {
			return usage()
		}
		return finalize(args[1], args[2])
	case "verify":
		if len(args) != 3 {
			return usage()
		}
		return verify(args[1], args[2])
	case "sign":
		// usage: release sign VERSION OUTPUT_DIR TRUST_ROOT KEY
		if len(args) != 5 {
			return usage()
		}
		key, err := readBoundedRelease(args[4], 64<<10)
		if err != nil {
			return errors.New("release signing key is unavailable")
		}
		passphrase, err := ReadSigningPassphrase(stderr)
		if err != nil {
			return errors.New("release signing passphrase is unavailable")
		}
		return sign(args[1], args[2], args[3], key, passphrase, stdout)
	case "verify-signature":
		// usage: release verify-signature VERSION OUTPUT_DIR TRUST_ROOT TRUST_ROOT_DIGEST
		if len(args) != 5 {
			return usage()
		}
		return verifySignature(args[1], args[2], args[3], args[4], stdout)
	default:
		return usage()
	}
}

// ReadSigningPassphrase is supplied by the command layer, which owns terminal
// access. It is a variable so tests can drive signing without a terminal; the
// production binary installs a terminal-only prompt.
var ReadSigningPassphrase = func(io.Writer) ([]byte, error) {
	return nil, errors.New("no release signing passphrase reader is installed")
}

func usage() error {
	return errors.New("usage: prufyx-maintainer release <test|binary|smoke|source|finalize|verify|sign|verify-signature> ...")
}

func root() (string, error) {
	out, err := command("", "git", "rev-parse", "--show-toplevel")
	if err != nil {
		return "", errors.New("run this command in a Git checkout")
	}
	return filepath.EvalSymlinks(strings.TrimSpace(string(out)))
}
func command(dir, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), commandTimeout)
	defer cancel()
	c := exec.CommandContext(ctx, name, args...)
	c.Dir = dir
	c.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=vendor -buildvcs=false")
	out, err := c.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			return nil, fmt.Errorf("%s exceeded the maintainer command deadline", name)
		}
		return nil, fmt.Errorf("%s failed: %w", name, err)
	}
	return out, nil
}
func goPath() (string, error) {
	p, err := exec.LookPath("go")
	if err != nil {
		return "", errors.New("Go executable is unavailable")
	}
	return filepath.EvalSymlinks(p)
}
func checkout(repo string) (string, error) {
	head, err := command(repo, "git", "rev-parse", "--verify", "HEAD")
	if err != nil {
		return "", errors.New("HEAD is unavailable")
	}
	revision := strings.TrimSpace(string(head))
	if len(revision) != 40 || strings.Trim(revision, "0123456789abcdef") != "" {
		return "", errors.New("HEAD is not an exact lowercase Git revision")
	}
	porcelain, err := command(repo, "git", "status", "--porcelain=v1", "--untracked-files=all", "--ignored")
	if err != nil || len(porcelain) != 0 {
		return "", errors.New("checkout is not clean")
	}
	if expected := os.Getenv("EXPECTED_REVISION"); expected != "" && expected != revision {
		return "", errors.New("checked-out revision differs from EXPECTED_REVISION")
	}
	return revision, nil
}
func toolchain(repo string) (string, error) {
	g, err := goPath()
	if err != nil {
		return "", err
	}
	v, err := command("", g, "env", "GOVERSION")
	if err != nil || strings.TrimSpace(string(v)) != requiredGo {
		return "", fmt.Errorf("Go toolchain must be %s", requiredGo)
	}
	exp, err := command("", g, "env", "GOEXPERIMENT")
	if err != nil || strings.TrimSpace(string(exp)) != "" {
		return "", errors.New("release builds require empty GOEXPERIMENT")
	}
	m, err := command(filepath.Join(repo, "cli"), g, "list", "-mod=vendor", "-m")
	if err != nil || strings.TrimSpace(string(m)) != modulePath {
		return "", errors.New("release module identity differs")
	}
	if _, err = command(filepath.Join(repo, "cli"), g, "list", "-mod=vendor", "-deps", entrypoint); err != nil {
		return "", errors.New("vendored release module closure is inconsistent")
	}
	return g, nil
}
func sourceInputs(repo, goBin string) error {
	for _, name := range []string{"LICENSE", "NOTICE", "THIRD-PARTY.md", "LICENSES/Go-BSD-3-Clause.txt"} {
		i, err := os.Lstat(filepath.Join(repo, name))
		if err != nil || !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 {
			return errors.New("required legal input is unavailable")
		}
	}
	license, err := os.ReadFile(filepath.Join(repo, "LICENSES/Go-BSD-3-Clause.txt"))
	if err != nil {
		return errors.New("cannot read Go license")
	}
	goroot, err := command("", goBin, "env", "GOROOT")
	if err != nil {
		return errors.New("cannot locate Go root")
	}
	actual, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(goroot)), "LICENSE"))
	if err != nil || string(license) != string(actual) {
		return errors.New("repository Go license differs from selected toolchain")
	}
	found := false
	err = filepath.WalkDir(filepath.Join(repo, "LICENSES"), func(_ string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Type()&os.ModeSymlink != 0 || (!d.IsDir() && !d.Type().IsRegular()) {
			return errors.New("LICENSES contains unsupported entry")
		}
		if d.Type().IsRegular() {
			found = true
		}
		return nil
	})
	if err != nil || !found {
		return errors.New("LICENSES inventory is invalid")
	}
	return nil
}
func versionOK(v string) bool {
	if !strings.HasPrefix(v, "v") {
		return false
	}
	x := strings.TrimPrefix(v, "v")
	main, pre, build := x, "", ""
	if plus := strings.IndexByte(x, '+'); plus >= 0 {
		main, build = x[:plus], x[plus+1:]
		if build == "" || strings.Contains(build, "+") || !semverIdentifiers(build, false) {
			return false
		}
	}
	if dash := strings.IndexByte(main, '-'); dash >= 0 {
		main, pre = main[:dash], main[dash+1:]
		if pre == "" || !semverIdentifiers(pre, true) {
			return false
		}
	}
	p := strings.Split(main, ".")
	if len(p) != 3 {
		return false
	}
	for _, n := range p {
		if n == "" || (len(n) > 1 && n[0] == '0') {
			return false
		}
		for _, r := range n {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func semverIdentifiers(value string, rejectNumericLeadingZero bool) bool {
	for _, identifier := range strings.Split(value, ".") {
		if identifier == "" {
			return false
		}
		numeric := true
		for _, r := range identifier {
			if !(r >= '0' && r <= '9') && !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && r != '-' {
				return false
			}
			if r < '0' || r > '9' {
				numeric = false
			}
		}
		if rejectNumericLeadingZero && numeric && len(identifier) > 1 && identifier[0] == '0' {
			return false
		}
	}
	return true
}
func target(t string) (string, string, error) {
	switch t {
	case "linux-amd64":
		return "linux", "amd64", nil
	case "linux-arm64":
		return "linux", "arm64", nil
	default:
		return "", "", errors.New("release target must be linux-amd64 or linux-arm64")
	}
}
func outputDir(repo, raw string) (*outputDirectory, error) {
	return openOutputDirectory(repo, raw)
}

func within(root, candidate string) bool {
	rel, err := filepath.Rel(root, candidate)
	return err == nil && (rel == "." || (!strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."))
}

func stage(repo, goBin string, native bool) (string, string, string, error) {
	work, err := os.MkdirTemp("", "prufyx-community-release-*")
	if err != nil {
		return "", "", "", err
	}
	manifest := filepath.Join(work, "SOURCE-MANIFEST.json")
	staged := filepath.Join(work, "source")
	o := releasegate.Options{SourceRoot: repo, PolicyPath: filepath.Join(repo, policyRel), Go: goBin, OutputPath: manifest}
	if _, err = releasegate.Generate(o); err != nil {
		os.RemoveAll(work)
		return "", "", "", fmt.Errorf("release manifest: %w", err)
	}
	o.ManifestPath = manifest
	o.OutputPath = staged
	o.RunNativeChecks = native
	if _, err = releasegate.Stage(o); err != nil {
		os.RemoveAll(work)
		return "", "", "", fmt.Errorf("release source stage: %w", err)
	}
	return work, manifest, staged, nil
}
func digest(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(h[:]), nil
}

type tarEntry struct {
	disk, name string
	dir        bool
	mode       fs.FileMode
	size       int64
}

func entries(root, prefix string) ([]tarEntry, error) {
	var out []tarEntry
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		name := filepath.ToSlash(rel)
		if name == "." {
			name = "."
		}
		if prefix != "" {
			if name == "." {
				name = strings.TrimSuffix(prefix, "/")
			} else {
				name = prefix + "/" + name
			}
		}
		i, e := d.Info()
		if e != nil {
			return e
		}
		if i.Mode()&os.ModeSymlink != 0 || (!i.IsDir() && !i.Mode().IsRegular()) {
			return errors.New("archive source contains unsupported entry")
		}
		out = append(out, tarEntry{path, name, i.IsDir(), i.Mode(), i.Size()})
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].name < out[j].name })
	return out, err
}
func writeTar(root, prefix string, dst io.Writer, epoch time.Time) error {
	es, err := entries(root, prefix)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(dst)
	for _, e := range es {
		n := e.name
		if e.dir && !strings.HasSuffix(n, "/") {
			n += "/"
		}
		mode := int64(0644)
		typ := byte(tar.TypeReg)
		if e.dir {
			mode = 0755
			typ = tar.TypeDir
		} else if e.mode.Perm()&0111 != 0 {
			mode = 0755
		}
		h := &tar.Header{Name: n, Mode: mode, Size: e.size, Uid: 0, Gid: 0, ModTime: epoch, Typeflag: typ, Format: tar.FormatGNU}
		if err := tw.WriteHeader(h); err != nil {
			return err
		}
		if !e.dir {
			src, err := os.Open(e.disk)
			if err != nil {
				return err
			}
			_, err = io.Copy(tw, src)
			closeErr := src.Close()
			if err != nil {
				return err
			}
			if closeErr != nil {
				return closeErr
			}
		}
	}
	return tw.Close()
}
func tarFile(root, prefix, out string, epoch time.Time) error {
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = writeTar(root, prefix, f, epoch); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
func tarGz(root, prefix, out string, epoch time.Time) error {
	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	g := gzip.NewWriter(f)
	g.Name = ""
	g.Comment = ""
	g.ModTime = time.Unix(0, 0)
	g.OS = 255
	if err = writeTar(root, prefix, g, epoch); err != nil {
		g.Close()
		f.Close()
		return err
	}
	if err = g.Close(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
func sourceDigest(stage, work string) (string, error) {
	p := filepath.Join(work, "source-tree.tar")
	if err := tarFile(stage, "", p, time.Unix(0, 0)); err != nil {
		return "", err
	}
	return digest(p)
}
func copyFile(source, dest string, perm fs.FileMode) error {
	b, e := os.ReadFile(source)
	if e != nil {
		return e
	}
	return os.WriteFile(dest, b, perm)
}
func epoch(repo, revision string) (time.Time, error) {
	out, e := command(repo, "git", "show", "-s", "--format=%ct", revision)
	if e != nil {
		return time.Time{}, e
	}
	var n int64
	if _, e = fmt.Sscan(strings.TrimSpace(string(out)), &n); e != nil {
		return time.Time{}, e
	}
	return time.Unix(n, 0).UTC(), nil
}

func test(stdout, stderr io.Writer) error {
	repo, e := root()
	if e != nil {
		return e
	}
	rev, e := checkout(repo)
	if e != nil {
		return e
	}
	g, e := toolchain(repo)
	if e != nil {
		return e
	}
	if e = sourceInputs(repo, g); e != nil {
		return e
	}
	work, _, staged, e := stage(repo, g, true)
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	fmt.Fprintf(stderr, "testing revision %s on %s/%s\n", rev, runtime.GOOS, runtime.GOARCH)
	c := goTestCommand(g, staged, stdout, stderr)
	return c.Run()
}

func goTestCommand(goBin, staged string, stdout, stderr io.Writer) *exec.Cmd {
	c := exec.Command(goBin, "test", "-race", "./...", "-count=1")
	c.Dir = filepath.Join(staged, "cli")
	c.Env = append(os.Environ(), "CGO_ENABLED=1", "GOEXPERIMENT=", "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=vendor -buildvcs=false")
	c.Stdout = stdout
	c.Stderr = stderr
	return c
}

func binary(v, t, out string) (string, error) {
	if !versionOK(v) {
		return "", errors.New("version must be v-prefixed semantic version")
	}
	osName, arch, e := target(t)
	if e != nil {
		return "", e
	}
	repo, e := root()
	if e != nil {
		return "", e
	}
	rev, e := checkout(repo)
	if e != nil {
		return "", e
	}
	g, e := toolchain(repo)
	if e != nil {
		return "", e
	}
	if e = sourceInputs(repo, g); e != nil {
		return "", e
	}
	hostOS, e := command("", g, "env", "GOHOSTOS")
	if e != nil {
		return "", e
	}
	hostArch, e := command("", g, "env", "GOHOSTARCH")
	if e != nil {
		return "", e
	}
	if strings.TrimSpace(string(hostOS)) != osName || strings.TrimSpace(string(hostArch)) != arch {
		return "", errors.New("binary build and smoke require a native target runner")
	}
	dst, e := outputDir(repo, out)
	if e != nil {
		return "", e
	}
	defer dst.Close()
	num := strings.TrimPrefix(v, "v")
	archiveName := fmt.Sprintf("prufyx-cli_%s_%s_%s.tar.gz", num, osName, arch)
	if e = dst.preflight(outputAsset{name: archiveName}); e != nil {
		return "", e
	}
	work, manifest, staged, e := stage(repo, g, false)
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(work)
	srcDigest, e := sourceDigest(staged, work)
	if e != nil {
		return "", e
	}
	manifestDigest, e := digest(manifest)
	if e != nil {
		return "", e
	}
	buildTime, e := epoch(repo, rev)
	if e != nil {
		return "", e
	}
	goVersion, e := command("", g, "env", "GOVERSION")
	if e != nil {
		return "", e
	}
	gv := strings.TrimSpace(string(goVersion))
	pkg := filepath.Join(work, fmt.Sprintf("prufyx-cli_%s_%s_%s", num, osName, arch))
	if e = os.Mkdir(pkg, 0755); e != nil {
		return "", e
	}
	bin := filepath.Join(pkg, "prufyx")
	marker := fmt.Sprintf("PRUFYX_BUILD_IDENTITY_V1_BEGIN|%s|release|%s|%s|%s|%s|%s|%s|UNPINNED|true|PRUFYX_BUILD_IDENTITY_V1_END", v, rev, srcDigest, manifestDigest, t, buildTime.Format(time.RFC3339), gv)
	ld := fmt.Sprintf("-buildid= -s -w -X %s/internal/buildidentity.Version=%s -X %s/internal/buildidentity.SourceRevision=%s -X %s/internal/buildidentity.SourceTreeDigest=%s -X %s/internal/buildidentity.AllowlistDigest=%s -X %s/internal/buildidentity.BuildProfile=%s -X %s/internal/buildidentity.BuildEpoch=%d -X %s/internal/buildidentity.TrustRootDigest=UNPINNED -X %s/internal/buildidentity.EmbeddedIdentity=%s", modulePath, v, modulePath, rev, modulePath, srcDigest, modulePath, manifestDigest, modulePath, t, modulePath, buildTime.Unix(), modulePath, modulePath, marker)
	c := exec.Command(g, "build", "-trimpath", "-buildvcs=false", "-ldflags", ld, "-o", bin, entrypoint)
	c.Dir = filepath.Join(staged, "cli")
	c.Env = append(os.Environ(), "CGO_ENABLED=0", "GOAMD64=v1", "GOARM64=v8.0", "GOEXPERIMENT=", "GOTOOLCHAIN=local", "GOWORK=off", "GOPROXY=off", "GOSUMDB=off", "GOFLAGS=-mod=vendor -buildvcs=false", "SOURCE_DATE_EPOCH="+fmt.Sprint(buildTime.Unix()), "GOOS="+osName, "GOARCH="+arch)
	if output, e := c.CombinedOutput(); e != nil {
		return "", fmt.Errorf("release build failed: %s", strings.TrimSpace(string(output)))
	}
	if e = os.Chmod(bin, 0755); e != nil {
		return "", e
	}
	meta := filepath.Join(pkg, "RELEASE-METADATA.json")
	if e = releasehelpers.WriteMetadata(releasehelpers.MetadataOptions{Output: meta, Version: v, Revision: rev, SourceTreeDigest: srcDigest, ManifestDigest: manifestDigest, Target: t, BuildEpoch: fmt.Sprint(buildTime.Unix()), GoVersion: gv}); e != nil {
		return "", e
	}
	for _, n := range []string{"LICENSE", "NOTICE", "THIRD-PARTY.md"} {
		if e = copyFile(filepath.Join(staged, n), filepath.Join(pkg, n), 0644); e != nil {
			return "", e
		}
	}
	if e = copyTree(filepath.Join(staged, "LICENSES"), filepath.Join(pkg, "LICENSES")); e != nil {
		return "", e
	}
	if e = writeBinaryGettingStarted(pkg); e != nil {
		return "", e
	}
	if e = os.WriteFile(filepath.Join(pkg, "SOURCE-REVISION"), []byte(rev+"\n"), 0644); e != nil {
		return "", e
	}
	versionOut, e := exec.Command(bin, "version").Output()
	if e != nil {
		return "", e
	}
	if e = releasehelpers.VerifyVersion(releasehelpers.VersionOptions{Metadata: meta, Report: versionOut}); e != nil {
		return "", e
	}
	demo := exec.Command(bin, "check", "prometheus-mode", "--demo", "--format", "json")
	raw, e := demo.Output()
	if exit, e2 := exitCode(e); e2 != nil || exit != 11 {
		return "", errors.New("Prometheus demo did not return UNKNOWN/11")
	}
	if e = releasehelpers.VerifyDemo(raw); e != nil {
		return "", e
	}
	if e = dst.createTarGz(archiveName, pkg, filepath.Base(pkg), buildTime); e != nil {
		return "", e
	}
	if e = dst.verifyBinding(); e != nil {
		return "", e
	}
	return dst.assetPath(archiveName), nil
}

func writeBinaryGettingStarted(pkg string) error {
	path := filepath.Join(pkg, "GETTING-STARTED.md")
	if err := os.WriteFile(path, releasehelpers.BinaryGettingStartedGuide(), 0644); err != nil {
		return err
	}
	return os.Chmod(path, 0644)
}

func exitCode(e error) (int, error) {
	if e == nil {
		return 0, nil
	}
	var x *exec.ExitError
	if errors.As(e, &x) {
		return x.ExitCode(), nil
	}
	return 0, e
}
func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		rel, _ := filepath.Rel(src, path)
		to := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(to, 0755)
		}
		if !d.Type().IsRegular() || d.Type()&os.ModeSymlink != 0 {
			return errors.New("source tree contains unsupported entry")
		}
		return copyFile(path, to, 0644)
	})
}

func source(v, out string) (string, error) {
	if !versionOK(v) {
		return "", errors.New("version must be v-prefixed semantic version")
	}
	repo, e := root()
	if e != nil {
		return "", e
	}
	rev, e := checkout(repo)
	if e != nil {
		return "", e
	}
	g, e := goPath()
	if e != nil {
		return "", e
	}
	if e = sourceInputs(repo, g); e != nil {
		return "", e
	}
	dst, e := outputDir(repo, out)
	if e != nil {
		return "", e
	}
	defer dst.Close()
	num := strings.TrimPrefix(v, "v")
	archiveName := fmt.Sprintf("prufyx-cli_%s_source.tar.gz", num)
	if e = dst.preflight(
		outputAsset{name: archiveName},
		outputAsset{name: "SOURCE-MANIFEST.json", replace: true},
		outputAsset{name: "SOURCE-REVISION", replace: true},
		outputAsset{name: "SOURCE-TREE.sha256", replace: true},
	); e != nil {
		return "", e
	}
	work, manifest, staged, e := stage(repo, g, false)
	if e != nil {
		return "", e
	}
	defer os.RemoveAll(work)
	d, e := sourceDigest(staged, work)
	if e != nil {
		return "", e
	}
	if e = dst.createTarGz(archiveName, staged, fmt.Sprintf("prufyx-cli_%s_source", num), time.Unix(0, 0)); e != nil {
		return "", e
	}
	manifestBytes, e := os.ReadFile(manifest)
	if e != nil {
		return "", e
	}
	if e = dst.replace("SOURCE-MANIFEST.json", 0o644, writeBytes(manifestBytes)); e != nil {
		return "", e
	}
	if e = dst.replace("SOURCE-REVISION", 0o644, writeBytes([]byte(rev+"\n"))); e != nil {
		return "", e
	}
	if e = dst.replace("SOURCE-TREE.sha256", 0o644, writeBytes(sourceTreeChecksum(d))); e != nil {
		return "", e
	}
	if e = dst.verifyBinding(); e != nil {
		return "", e
	}
	return dst.assetPath(archiveName), nil
}

func sourceTreeChecksum(digest string) []byte {
	return []byte(strings.TrimPrefix(digest, "sha256:") + "  source-tree.tar\n")
}

func finalize(v, out string) error {
	if !versionOK(v) {
		return errors.New("version must be v-prefixed semantic version")
	}
	repo, e := root()
	if e != nil {
		return e
	}
	rev, e := checkout(repo)
	if e != nil {
		return e
	}
	g, e := toolchain(repo)
	if e != nil {
		return e
	}
	if e = sourceInputs(repo, g); e != nil {
		return e
	}
	dst, e := outputDir(repo, out)
	if e != nil {
		return e
	}
	defer dst.Close()
	names := releaseAssets(v)
	assets := make([]outputAsset, 0, len(names)+1)
	for _, name := range names {
		switch name {
		case "LICENSE", "NOTICE", "THIRD-PARTY.md", "Go-BSD-3-Clause.txt", "SBOM.spdx.json":
			assets = append(assets, outputAsset{name: name, replace: true})
		default:
			assets = append(assets, outputAsset{name: name, required: true})
		}
	}
	assets = append(assets, outputAsset{name: "SHA256SUMS"})
	if e = dst.preflightExact(assets...); e != nil {
		return e
	}
	generated := make(map[string][]byte, 5)
	for _, name := range []string{"LICENSE", "NOTICE", "THIRD-PARTY.md"} {
		generated[name], e = os.ReadFile(filepath.Join(repo, name))
		if e != nil {
			return e
		}
	}
	generated["Go-BSD-3-Clause.txt"], e = os.ReadFile(filepath.Join(repo, "LICENSES", "Go-BSD-3-Clause.txt"))
	if e != nil {
		return e
	}
	bt, e := epoch(repo, rev)
	if e != nil {
		return e
	}
	gv, e := command("", g, "env", "GOVERSION")
	if e != nil {
		return e
	}
	work, e := os.MkdirTemp("", "prufyx-community-finalize-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	sbom := filepath.Join(work, "SBOM.spdx.json")
	// The distributable archives already exist at this point (preflightExact
	// requires them), so the SBOM can be bound to the exact final artifacts
	// rather than to the shipping policy alone. It deliberately omits itself
	// and SHA256SUMS, which are derived from it.
	if e = releasehelpers.WriteSBOM(releasehelpers.SBOMOptions{Output: sbom, Version: v, Revision: rev, BuildEpoch: fmt.Sprint(bt.Unix()), GoVersion: strings.TrimSpace(string(gv)), Policy: filepath.Join(repo, policyRel), ArtifactDir: dst.path, Artifacts: distributableArchives(v)}); e != nil {
		return e
	}
	generated["SBOM.spdx.json"], e = os.ReadFile(sbom)
	if e != nil {
		return e
	}
	for _, name := range []string{"LICENSE", "NOTICE", "THIRD-PARTY.md", "Go-BSD-3-Clause.txt", "SBOM.spdx.json"} {
		mode := uint32(0o644)
		if name == "SBOM.spdx.json" {
			mode = 0o600
		}
		if e = dst.replace(name, mode, writeBytes(generated[name])); e != nil {
			return e
		}
	}
	var sums bytes.Buffer
	for _, n := range names {
		d, e := dst.digest(n)
		if e != nil {
			return e
		}
		if _, e = fmt.Fprintf(&sums, "%s  %s\n", strings.TrimPrefix(d, "sha256:"), n); e != nil {
			return e
		}
	}
	if e = dst.create("SHA256SUMS", 0o644, writeBytes(sums.Bytes())); e != nil {
		return e
	}
	return dst.verifyBinding()
}

func smoke(v, t, out string, stdout io.Writer) error {
	if !versionOK(v) {
		return errors.New("version must be v-prefixed semantic version")
	}
	osName, arch, e := target(t)
	if e != nil {
		return e
	}
	dst, e := filepath.EvalSymlinks(out)
	if e != nil {
		return errors.New("archive output directory is unavailable")
	}
	num := strings.TrimPrefix(v, "v")
	archive := filepath.Join(dst, fmt.Sprintf("prufyx-cli_%s_%s_%s.tar.gz", num, osName, arch))
	a, e := os.Lstat(archive)
	if e != nil || !a.Mode().IsRegular() || a.Mode()&os.ModeSymlink != 0 {
		return errors.New("native archive is unavailable")
	}
	work, e := os.MkdirTemp("", "prufyx-community-smoke-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	if e = extract(archive, work); e != nil {
		return e
	}
	pkg := filepath.Join(work, fmt.Sprintf("prufyx-cli_%s_%s_%s", num, osName, arch))
	if e = validateSmokeLayout(work, pkg); e != nil {
		return e
	}
	bin := filepath.Join(pkg, "prufyx")
	i, e := os.Lstat(bin)
	if e != nil || !i.Mode().IsRegular() || i.Mode()&os.ModeSymlink != 0 {
		return errors.New("archive package layout is invalid")
	}
	if e = os.Chmod(bin, 0755); e != nil {
		return e
	}
	home := filepath.Join(work, "home")
	if e = os.Mkdir(home, 0700); e != nil {
		return e
	}
	version := exec.Command(bin, "version")
	version.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "TZ=UTC"}
	raw, e := version.Output()
	if e != nil {
		return e
	}
	if e = releasehelpers.VerifyVersion(releasehelpers.VersionOptions{Metadata: filepath.Join(pkg, "RELEASE-METADATA.json"), Report: raw}); e != nil {
		return e
	}
	values := filepath.Join(work, "cert-manager-values.json")
	if e = os.WriteFile(values, []byte("{\"prometheus\":{\"servicemonitor\":{\"path\":\"/release-smoke\"}}}\n"), 0600); e != nil {
		return e
	}
	cert := exec.Command(bin, "check", "cert-manager-values", "--from", "1.20.3", "--to", "1.21.1", "--values", values, "--format", "json")
	cert.Env = version.Env
	cr, e := cert.Output()
	xc, ec := exitCode(e)
	if ec != nil || xc != 10 {
		return errors.New("cert-manager smoke did not return BLOCKED/10")
	}
	certPath := filepath.Join(work, "cert.json")
	if e = os.WriteFile(certPath, cr, 0600); e != nil {
		return e
	}
	if e = releasehelpers.VerifyScoped("cert-manager", certPath); e != nil {
		return e
	}
	k := filepath.Join(work, "karmada.json")
	if e = os.WriteFile(k, []byte("{\"apiVersion\":\"policy.karmada.io/v1alpha1\",\"kind\":\"PropagationPolicy\",\"metadata\":{\"name\":\"release-smoke\"},\"spec\":{\"failover\":{\"application\":{\"purgeMode\":\"Immediately\"}}}}\n"), 0600); e != nil {
		return e
	}
	prepared := filepath.Join(work, "karmada-input.json")
	p := exec.Command(bin, "prepare", "cncf", "--project", "karmada", "--input", k, "--from", "1.18.3", "--to", "1.19.0", "--distribution", "official_upstream", "--target-policy-crd-admission", "required", "--format", "input")
	p.Env = version.Env
	pr, e := p.Output()
	if e != nil {
		return e
	}
	if e = os.WriteFile(prepared, pr, 0600); e != nil {
		return e
	}
	check := exec.Command(bin, "check", "cncf", "--project", "karmada", "--input", prepared, "--now", "2026-09-09T05:00:00Z", "--format", "json")
	check.Env = version.Env
	kr, e := check.Output()
	xc, ec = exitCode(e)
	if ec != nil || xc != 10 {
		return errors.New("Karmada smoke did not return BLOCKED/10")
	}
	kp := filepath.Join(work, "karmada-report.json")
	if e = os.WriteFile(kp, kr, 0600); e != nil {
		return e
	}
	if e = releasehelpers.VerifyScoped("karmada", kp); e != nil {
		return e
	}
	d, e := digest(archive)
	if e != nil {
		return e
	}
	return releasehelpers.WriteSmokeReceiptTo(stdout, releasehelpers.SmokeReceiptOptions{Version: v, Target: t, ArchiveDigest: d, Metadata: filepath.Join(pkg, "RELEASE-METADATA.json")})
}

func validateSmokeLayout(work, pkg string) error {
	entries, err := os.ReadDir(work)
	if err != nil || len(entries) != 1 || entries[0].Name() != filepath.Base(pkg) || !entries[0].IsDir() {
		return errors.New("archive extraction contains unexpected top-level paths")
	}
	for _, name := range []string{"go.mod", ".git"} {
		if _, err := os.Lstat(filepath.Join(pkg, name)); err == nil || !os.IsNotExist(err) {
			return errors.New("archive package contains source or repository metadata")
		}
	}
	return nil
}

func extract(archive, dst string) error {
	f, e := os.Open(archive)
	if e != nil {
		return e
	}
	defer f.Close()
	g, e := gzip.NewReader(f)
	if e != nil {
		return e
	}
	defer g.Close()
	tr := tar.NewReader(g)
	for {
		h, e := tr.Next()
		if e == io.EOF {
			return nil
		}
		if e != nil {
			return e
		}
		if filepath.IsAbs(h.Name) || strings.Contains(h.Name, "..") || strings.Contains(h.Name, "//") {
			return errors.New("archive contains unsafe member")
		}
		to := filepath.Join(dst, filepath.FromSlash(h.Name))
		if !strings.HasPrefix(to, dst+string(filepath.Separator)) {
			return errors.New("archive member escapes output")
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if e = os.MkdirAll(to, 0755); e != nil {
				return e
			}
		case tar.TypeReg:
			if e = os.MkdirAll(filepath.Dir(to), 0755); e != nil {
				return e
			}
			o, e := os.OpenFile(to, os.O_CREATE|os.O_EXCL|os.O_WRONLY, fs.FileMode(h.Mode))
			if e != nil {
				return e
			}
			_, e = io.Copy(o, tr)
			ce := o.Close()
			if e != nil {
				return e
			}
			if ce != nil {
				return ce
			}
		default:
			return errors.New("archive contains unsupported member")
		}
	}
}

func verify(v, out string) error {
	if !versionOK(v) {
		return errors.New("version must be v-prefixed semantic version")
	}
	repo, e := root()
	if e != nil {
		return e
	}
	rev, e := checkout(repo)
	if e != nil {
		return e
	}
	g, e := toolchain(repo)
	if e != nil {
		return e
	}
	if e = sourceInputs(repo, g); e != nil {
		return e
	}
	dst, e := filepath.EvalSymlinks(out)
	if e != nil {
		return errors.New("release output directory unavailable")
	}
	num := strings.TrimPrefix(v, "v")
	assets := releaseAssets(v)
	names := append([]string{"SHA256SUMS"}, assets...)
	actual, err := os.ReadDir(dst)
	if err != nil {
		return err
	}
	// A signed release additionally carries the release statement and its
	// detached envelope. Both are optional here: `release verify` proves
	// derivation, and `release verify-signature` proves authority. Neither
	// substitutes for the other.
	allowed := map[string]bool{releasesign.StatementName: true, releasesign.EnvelopeName: true}
	extra := 0
	for _, entry := range actual {
		if allowed[entry.Name()] {
			extra++
		}
	}
	if len(actual) != len(names)+extra {
		return errors.New("release output contains unexpected files")
	}
	for _, n := range names {
		if _, e := os.Lstat(filepath.Join(dst, n)); e != nil {
			return errors.New("release output contains missing file")
		}
	}
	if b, e := os.ReadFile(filepath.Join(dst, "SOURCE-REVISION")); e != nil || string(b) != rev+"\n" {
		return errors.New("source revision asset mismatch")
	}
	work, manifest, staged, e := stage(repo, g, false)
	if e != nil {
		return e
	}
	defer os.RemoveAll(work)
	expected, e := sourceDigest(staged, work)
	if e != nil {
		return e
	}
	tree, e := os.ReadFile(filepath.Join(dst, "SOURCE-TREE.sha256"))
	if e != nil || string(tree) != string(sourceTreeChecksum(expected)) {
		return errors.New("source tree digest asset mismatch")
	}
	if b, e := os.ReadFile(manifest); e != nil {
		return e
	} else if c, e := os.ReadFile(filepath.Join(dst, "SOURCE-MANIFEST.json")); e != nil || string(b) != string(c) {
		return errors.New("source manifest differs from exact policy and source bytes")
	}
	tmpSource := filepath.Join(work, "expected-source.tar.gz")
	if e = tarGz(staged, fmt.Sprintf("prufyx-cli_%s_source", num), tmpSource, time.Unix(0, 0)); e != nil {
		return e
	}
	if a, e := os.ReadFile(tmpSource); e != nil {
		return e
	} else if b, e := os.ReadFile(filepath.Join(dst, fmt.Sprintf("prufyx-cli_%s_source.tar.gz", num))); e != nil || string(a) != string(b) {
		return errors.New("source archive differs from exact source stage")
	}
	bt, e := epoch(repo, rev)
	if e != nil {
		return e
	}
	gvb, e := command("", g, "env", "GOVERSION")
	if e != nil {
		return e
	}
	sbom := filepath.Join(work, "SBOM.spdx.json")
	if e = releasehelpers.WriteSBOM(releasehelpers.SBOMOptions{Output: sbom, Version: v, Revision: rev, BuildEpoch: fmt.Sprint(bt.Unix()), GoVersion: strings.TrimSpace(string(gvb)), Policy: filepath.Join(repo, policyRel), ArtifactDir: dst, Artifacts: distributableArchives(v)}); e != nil {
		return e
	}
	if a, e := os.ReadFile(sbom); e != nil {
		return e
	} else if b, e := os.ReadFile(filepath.Join(dst, "SBOM.spdx.json")); e != nil || string(a) != string(b) {
		return errors.New("SBOM differs from exact release inputs")
	}
	for _, tt := range []string{"linux-amd64", "linux-arm64"} {
		osName, arch, _ := target(tt)
		archive := filepath.Join(dst, fmt.Sprintf("prufyx-cli_%s_%s_%s.tar.gz", num, osName, arch))
		if e = releasehelpers.VerifyArchive(releasehelpers.ArchiveOptions{Archive: archive, PackageName: fmt.Sprintf("prufyx-cli_%s_%s_%s", num, osName, arch), RepositoryRoot: repo, BuildEpoch: fmt.Sprint(bt.Unix())}); e != nil {
			return e
		}
	}
	return verifySums(dst, assets)
}

func releaseAssets(version string) []string {
	num := strings.TrimPrefix(version, "v")
	names := []string{"LICENSE", "NOTICE", "THIRD-PARTY.md", "Go-BSD-3-Clause.txt", "SBOM.spdx.json", "SOURCE-MANIFEST.json", "SOURCE-REVISION", "SOURCE-TREE.sha256", fmt.Sprintf("prufyx-cli_%s_linux_amd64.tar.gz", num), fmt.Sprintf("prufyx-cli_%s_linux_arm64.tar.gz", num), fmt.Sprintf("prufyx-cli_%s_source.tar.gz", num)}
	sort.Strings(names)
	return names
}

// distributableArchives is the subset of release assets that a downloader
// actually executes or builds from. The SBOM is bound to exactly these bytes.
// SBOM.spdx.json and SHA256SUMS are excluded because both are derived from
// them, and a document cannot record its own digest.
func distributableArchives(version string) []string {
	num := strings.TrimPrefix(version, "v")
	names := []string{
		fmt.Sprintf("prufyx-cli_%s_linux_amd64.tar.gz", num),
		fmt.Sprintf("prufyx-cli_%s_linux_arm64.tar.gz", num),
		fmt.Sprintf("prufyx-cli_%s_source.tar.gz", num),
	}
	sort.Strings(names)
	return names
}

// signedCoveredAssets is every asset a release statement binds: the full
// release asset set plus SHA256SUMS. The statement and envelope themselves are
// excluded, since the envelope covers the statement.
func signedCoveredAssets(version string) []string {
	names := append([]string{"SHA256SUMS"}, releaseAssets(version)...)
	sort.Strings(names)
	return names
}

// releaseIdentity re-derives the exact release identity from the checkout so a
// statement is never signed over numbers a caller supplied by hand.
func releaseIdentity(v string) (repoPath, revision, goVersion string, buildEpoch int64, sourceTree, manifestDigest string, err error) {
	repo, err := root()
	if err != nil {
		return "", "", "", 0, "", "", err
	}
	rev, err := checkout(repo)
	if err != nil {
		return "", "", "", 0, "", "", err
	}
	g, err := toolchain(repo)
	if err != nil {
		return "", "", "", 0, "", "", err
	}
	if err = sourceInputs(repo, g); err != nil {
		return "", "", "", 0, "", "", err
	}
	work, manifest, staged, err := stage(repo, g, false)
	if err != nil {
		return "", "", "", 0, "", "", err
	}
	defer os.RemoveAll(work)
	tree, err := sourceDigest(staged, work)
	if err != nil {
		return "", "", "", 0, "", "", err
	}
	md, err := digest(manifest)
	if err != nil {
		return "", "", "", 0, "", "", err
	}
	bt, err := epoch(repo, rev)
	if err != nil {
		return "", "", "", 0, "", "", err
	}
	gv, err := command("", g, "env", "GOVERSION")
	if err != nil {
		return "", "", "", 0, "", "", err
	}
	return repo, rev, strings.TrimSpace(string(gv)), bt.Unix(), tree, md, nil
}

// sign binds the finalized release output to an offline Ed25519 signature.
// It refuses to sign an output that `release verify` would reject, so an
// operator cannot sign a set that does not derive from the exact checkout.
func sign(v, out, trustRootPath string, key []byte, passphrase []byte, stdout io.Writer) error {
	defer func() {
		for i := range passphrase {
			passphrase[i] = 0
		}
	}()
	if !versionOK(v) {
		return errors.New("version must be v-prefixed semantic version")
	}
	if err := verify(v, out); err != nil {
		return fmt.Errorf("refusing to sign an unverified release output: %w", err)
	}
	_, rev, gv, buildEpoch, tree, manifestDigest, err := releaseIdentity(v)
	if err != nil {
		return err
	}
	dst, err := filepath.EvalSymlinks(out)
	if err != nil {
		return errors.New("release output directory unavailable")
	}
	trustRoot, err := readBoundedRelease(trustRootPath, releasesign.MaxTrustRootBytes)
	if err != nil {
		return errors.New("release trust root is unavailable")
	}
	artifacts, err := releasesign.DirectoryArtifacts(dst, signedCoveredAssets(v))
	if err != nil {
		return errors.New("release artifacts could not be bound")
	}
	statement, err := releasesign.BuildStatement(releasesign.StatementOptions{
		Version: v, SourceRevision: rev, SourceTreeDigest: tree, ReleaseManifestDigest: manifestDigest,
		GoVersion: gv, BuildEpoch: buildEpoch,
		Expires:   time.Now().UTC().Add(365 * 24 * time.Hour).Truncate(time.Second).Format(time.RFC3339),
		TrustRoot: trustRoot, Artifacts: artifacts,
	})
	if err != nil {
		return errors.New("release statement could not be built")
	}
	envelope, err := releasesign.Sign(releasesign.SignOptions{
		Statement: statement, TrustRoot: trustRoot, EncryptedKey: key, Passphrase: passphrase,
	})
	if err != nil {
		return errors.New("release statement could not be signed")
	}
	if err := writeNewRelease(dst, releasesign.StatementName, statement); err != nil {
		return err
	}
	if err := writeNewRelease(dst, releasesign.EnvelopeName, envelope); err != nil {
		return err
	}
	result, err := releasesign.VerifyDirectory(dst, releasesign.VerifyOptions{
		Statement: statement, Envelope: envelope, TrustRoot: trustRoot,
		TrustRootDigest: mustTrustRootDigest(trustRoot),
	})
	if err != nil {
		return errors.New("signed release output did not verify")
	}
	_, err = fmt.Fprintln(stdout, releasesign.Describe(result))
	return err
}

// verifySignature checks a signed release output against an independently
// supplied trust root and its independently established digest.
func verifySignature(v, out, trustRootPath, trustRootDigest string, stdout io.Writer) error {
	if !versionOK(v) {
		return errors.New("version must be v-prefixed semantic version")
	}
	dst, err := filepath.EvalSymlinks(out)
	if err != nil {
		return errors.New("release output directory unavailable")
	}
	trustRoot, err := readBoundedRelease(trustRootPath, releasesign.MaxTrustRootBytes)
	if err != nil {
		return errors.New("release trust root is unavailable")
	}
	statement, err := readBoundedRelease(filepath.Join(dst, releasesign.StatementName), releasesign.MaxStatementBytes)
	if err != nil {
		return errors.New("release statement is unavailable")
	}
	envelope, err := readBoundedRelease(filepath.Join(dst, releasesign.EnvelopeName), releasesign.MaxEnvelopeBytes)
	if err != nil {
		return errors.New("release signature is unavailable")
	}
	result, err := releasesign.VerifyDirectory(dst, releasesign.VerifyOptions{
		Statement: statement, Envelope: envelope, TrustRoot: trustRoot, TrustRootDigest: trustRootDigest,
	})
	if err != nil {
		return errors.New("release signature verification failed")
	}
	if result.Version != v {
		return errors.New("release signature covers a different version")
	}
	// Confirm the signed set is exactly the expected release asset set: a
	// valid signature over a short list must not pass as a full release.
	expected := signedCoveredAssets(v)
	if result.Artifacts != len(expected) {
		return errors.New("release signature covers an unexpected asset set")
	}
	_, err = fmt.Fprintln(stdout, releasesign.Describe(result))
	return err
}

func mustTrustRootDigest(raw []byte) string {
	d, err := releasesign.TrustRootDigest(raw)
	if err != nil {
		return ""
	}
	return d
}

// readBoundedRelease reads one bounded regular file without following a
// symlink.
func readBoundedRelease(path string, limit int) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > int64(limit) {
		return nil, errors.New("bounded release input is unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, int64(limit)+1))
	if err != nil || int64(len(raw)) != info.Size() {
		return nil, errors.New("bounded release input changed while being read")
	}
	return raw, nil
}

// writeNewRelease creates one new 0644 release asset and never overwrites.
func writeNewRelease(dir, name string, raw []byte) error {
	file, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("refusing to overwrite %s", name)
	}
	if err := file.Chmod(0o644); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(raw); err != nil {
		file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func verifySums(dir string, expected []string) error {
	raw, e := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if e != nil {
		return e
	}
	names := make([]string, 0, len(expected))
	hashes := make([]string, 0, len(expected))
	for _, line := range bytes.SplitAfter(raw, []byte{'\n'}) {
		if len(line) == 0 {
			continue
		}
		if len(line) < 68 || line[64] != ' ' || line[65] != ' ' || line[len(line)-1] != '\n' {
			return errors.New("SHA256SUMS is invalid")
		}
		hash, name := string(line[:64]), string(line[66:len(line)-1])
		if strings.ToLower(hash) != hash || !isSHA256(hash) || name == "" || name != filepath.Base(name) || strings.ContainsAny(name, "/\\\x00\r\n") {
			return errors.New("SHA256SUMS is invalid")
		}
		names = append(names, name)
		hashes = append(hashes, hash)
	}
	if len(names) != len(expected) {
		return errors.New("SHA256SUMS is invalid")
	}
	for i, name := range names {
		if name != expected[i] {
			return errors.New("SHA256SUMS is invalid")
		}
		d, e := digest(filepath.Join(dir, name))
		if e != nil || strings.TrimPrefix(d, "sha256:") != hashes[i] {
			return errors.New("SHA256SUMS mismatch")
		}
	}
	return nil
}

func isSHA256(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}
