// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"crypto/sha1" //nolint:gosec // git blob ids are SHA-1 by definition; used to compare, not to authenticate
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/cncfcheck"
)

const subprojectsUsage = "subprojects: usage: prufyx-maintainer subprojects verify --root DIR   (needs network; maintainer review step, not CI)"

const (
	subprojectsRawHost = "raw.githubusercontent.com"
	subprojectsMaxBody = 8 << 20
)

// runSubprojects is the CNCF sub-project overlay verification: it re-fetches
// every cited file at its pinned commit and re-checks the committed claims.
// It writes nothing. Any miss refuses the row and the file (exit 1).
func runSubprojects(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] != "verify" {
		return &commandError{code: 2, message: subprojectsUsage}
	}
	flags := flag.NewFlagSet("subprojects verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", "", "repository root")
	if err := flags.Parse(args[1:]); err != nil || flags.NArg() != 0 || *root == "" {
		return &commandError{code: 2, message: subprojectsUsage, err: err}
	}
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	ok, err := verifySubprojects(ctx, *root, &rawFetcher{client: client}, stdout)
	if err != nil {
		return &commandError{code: 1, message: "subprojects verify: " + err.Error(), err: err}
	}
	if !ok {
		return &commandError{code: 1, message: "subprojects verify: FAIL", printed: false}
	}
	return nil
}

// fetcher returns the body of one raw URL. The production fetcher refuses any
// host but the raw host, any redirect and any non-200 answer.
type fetcher interface {
	Get(ctx context.Context, rawURL string) ([]byte, error)
}

type rawFetcher struct{ client *http.Client }

func (f *rawFetcher) Get(ctx context.Context, rawURL string) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.Scheme != "https" || parsed.Host != subprojectsRawHost || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, fmt.Errorf("refusing %q: not a plain https %s URL", rawURL, subprojectsRawHost)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: status %d (redirects are refused)", rawURL, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, subprojectsMaxBody+1))
	if err != nil {
		return nil, err
	}
	if len(body) > subprojectsMaxBody {
		return nil, fmt.Errorf("%s: body larger than %d bytes", rawURL, subprojectsMaxBody)
	}
	return body, nil
}

// verifySubprojects loads the committed overlay strictly, then checks every
// row against the fetched sources. It prints one line per row and one result
// line, and reports whether every row passed. A load failure is an error.
func verifySubprojects(ctx context.Context, root string, get fetcher, out io.Writer) (bool, error) {
	dir := filepath.Join(root, "cli", "internal", "cncfcheck", "data")
	raw, err := os.ReadFile(filepath.Join(dir, "cncf-subprojects.json"))
	if err != nil {
		return false, err
	}
	landscape, err := os.ReadFile(filepath.Join(dir, "landscape-projects.json"))
	if err != nil {
		return false, err
	}
	var doc struct {
		Projects []struct {
			Slug          string `json:"slug"`
			RepositoryURL string `json:"repositoryURL"`
		} `json:"projects"`
	}
	if err := json.Unmarshal(landscape, &doc); err != nil {
		return false, err
	}
	n := cncfcheck.SubprojectNeighbours{Landscape: map[string]string{}, OtherSlugs: map[string]bool{}, OtherRepos: map[string]bool{}}
	for _, p := range doc.Projects {
		n.Landscape[p.Slug] = p.RepositoryURL
	}
	overlay, err := cncfcheck.LoadSubprojects(raw, n)
	if err != nil {
		return false, err
	}
	failed := 0
	for _, row := range overlay.Rows {
		line, err := verifySubprojectRow(ctx, row, get)
		if err != nil {
			failed++
			fmt.Fprintf(out, "row %s: FAIL: %v\n", row.Slug, err)
			continue
		}
		fmt.Fprintln(out, line)
	}
	status := "OK"
	if failed > 0 {
		status = "FAIL"
	}
	fmt.Fprintf(out, "subprojects verify: %s rows=%d failed=%d subprojectDigest=%s rowsDigest=%s\n",
		status, len(overlay.Rows), failed, cncfcheck.SubprojectsFileDigest(raw), overlay.RowsDigest)
	return failed == 0, nil
}

func verifySubprojectRow(ctx context.Context, row cncfcheck.SubprojectRow, get fetcher) (string, error) {
	g := row.Governance
	body, err := get.Get(ctx, g.URL)
	if err != nil {
		return "", fmt.Errorf("governance fetch: %w", err)
	}
	text, lines, ok := cncfcheck.CitedLines(body, g.Line, g.LineEnd)
	if !ok {
		return "", fmt.Errorf("lines %d-%d are outside %s", g.Line, g.LineEnd, g.File)
	}
	if err := cncfcheck.CheckCitedLines(row, text, lines); err != nil {
		return "", err
	}
	licence, err := get.Get(ctx, row.License.Source)
	if err != nil {
		return "", fmt.Errorf("license fetch: %w", err)
	}
	if blob := gitBlobSHA(licence); blob != row.License.BlobSHA {
		return "", fmt.Errorf("license blob %s, committed %s", blob, row.License.BlobSHA)
	}
	if row.License.SPDX != "Apache-2.0" || !strings.Contains(string(licence), "Apache License") || !strings.Contains(string(licence), "Version 2.0") {
		return "", errors.New("license text is not recognised as the committed SPDX identifier")
	}
	return fmt.Sprintf("row %s: ok source=%s@%s L%d-%d lineSha256=%s marker=found repo=listed(%s%s) license=%s blob=%s",
		row.Slug, g.SourceKind, g.Commit, g.Line, g.LineEnd, g.LineSHA256, cncfcheck.SubprojectRepoPath(row), pathSuffix(row.RepoPath), row.License.SPDX, row.License.BlobSHA), nil
}

func pathSuffix(p string) string {
	if p == "" {
		return ""
	}
	return " path=" + p
}

func gitBlobSHA(b []byte) string {
	h := sha1.New() //nolint:gosec // see import
	fmt.Fprintf(h, "blob %d\x00", len(b))
	h.Write(b)
	return hex.EncodeToString(h.Sum(nil))
}
