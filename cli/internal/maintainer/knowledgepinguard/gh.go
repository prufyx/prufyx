// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepinguard

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

const (
	// PinPath is the pin file in the repository.
	PinPath = "cli/knowledge/oldest-supported-client.txt"

	maxAssets     = 64
	maxTotalBytes = 256 << 20
	maxRunsRead   = 30
)

// Runner runs the GitHub CLI with args and returns its standard output. The
// process must hold only a read-only token.
type Runner func(args ...string) ([]byte, error)

// GH is the Forge backed by the GitHub CLI.
type GH struct {
	Repo string // owner/name
	Run  Runner
	// WorkDir is an empty private directory for downloads.
	WorkDir string
}

func (g GH) api(path string, jq string) ([]byte, error) {
	args := []string{"api", "-X", "GET", path}
	if jq != "" {
		args = append(args, "--jq", jq)
	}
	return g.Run(args...)
}

func notFound(err error) bool { return err != nil && strings.Contains(err.Error(), "HTTP 404") }

// Release implements Forge.
func (g GH) Release(tag string) (*Release, error) {
	raw, err := g.api("repos/"+g.Repo+"/releases/tags/"+tag, "")
	if notFound(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return parseRelease(raw)
}

func parseRelease(raw []byte) (*Release, error) {
	var v struct {
		TagName   string `json:"tag_name"`
		Draft     bool   `json:"draft"`
		Immutable *bool  `json:"immutable"`
		Assets    []struct {
			Name string `json:"name"`
			Size int64  `json:"size"`
		} `json:"assets"`
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil, errors.New("the release response is not JSON")
	}
	r := &Release{TagName: v.TagName, Draft: v.Draft, Immutable: v.Immutable}
	for _, a := range v.Assets {
		r.Assets = append(r.Assets, Asset{Name: a.Name, Size: a.Size})
	}
	return r, nil
}

// TagCommit implements Forge. An annotated tag is followed once; anything
// that is not a commit after that is an error.
func (g GH) TagCommit(tag string) (string, error) {
	out, err := g.api("repos/"+g.Repo+"/git/ref/tags/"+tag, ".object | [.type, .sha] | @tsv")
	if err != nil {
		return "", err
	}
	typ, sha, ok := strings.Cut(strings.TrimSpace(string(out)), "\t")
	if !ok {
		return "", errors.New("unexpected tag reference response")
	}
	if typ == "tag" {
		out, err = g.api("repos/"+g.Repo+"/git/tags/"+sha, ".object | [.type, .sha] | @tsv")
		if err != nil {
			return "", err
		}
		typ, sha, ok = strings.Cut(strings.TrimSpace(string(out)), "\t")
		if !ok {
			return "", errors.New("unexpected annotated tag response")
		}
	}
	if typ != "commit" || !refRE.MatchString(sha) {
		return "", fmt.Errorf("the tag does not point to a commit (%s)", typ)
	}
	return sha, nil
}

// OnMain implements Forge: the merge base of main and the commit is the
// commit itself exactly when it is an ancestor of main.
func (g GH) OnMain(commit string) (bool, error) {
	if !refRE.MatchString(commit) {
		return false, errors.New("not a commit id")
	}
	out, err := g.api("repos/"+g.Repo+"/compare/main..."+commit, "[.status, .merge_base_commit.sha] | @tsv")
	if err != nil {
		return false, err
	}
	status, base, _ := strings.Cut(strings.TrimSpace(string(out)), "\t")
	return (status == "identical" || status == "behind") && base == commit, nil
}

// PreviousPin implements Forge: the pin at the head of the newest successful
// run of the publish workflow on main that has one.
func (g GH) PreviousPin() (string, bool, error) {
	out, err := g.api("repos/"+g.Repo+"/actions/workflows/knowledge-publish.yml/runs?branch=main&status=success&per_page=100", ".workflow_runs[].head_sha")
	if err != nil {
		return "", false, err
	}
	n := 0
	for _, sha := range strings.Fields(string(out)) {
		if !refRE.MatchString(sha) {
			return "", false, errors.New("unexpected run commit")
		}
		if n++; n > maxRunsRead {
			break
		}
		content, err := g.api("repos/"+g.Repo+"/contents/"+PinPath+"?ref="+sha, ".content")
		if notFound(err) {
			continue // the pin file did not exist at that run
		}
		if err != nil {
			return "", false, err
		}
		raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(content)), ""))
		if err != nil {
			return "", false, errors.New("the earlier pin file is not base64")
		}
		_, version, err := ParsePin(raw)
		if err != nil {
			return "", false, fmt.Errorf("the earlier pin file at %s is invalid: %v", sha, err)
		}
		return version, true, nil
	}
	return "", false, nil
}

// VerifyAssets implements Forge. SHA256SUMS must carry a provenance
// attestation of the release workflow for this tag and commit; every other
// asset must be listed in it with a matching digest, and nothing may be listed
// that is not an asset.
func (g GH) VerifyAssets(tag, commit string, r *Release) error {
	if len(r.Assets) == 0 || len(r.Assets) > maxAssets {
		return fmt.Errorf("release has %d assets", len(r.Assets))
	}
	var total int64
	names := map[string]bool{}
	for _, a := range r.Assets {
		if !assetName.MatchString(a.Name) || names[a.Name] {
			return fmt.Errorf("unusable asset name %q", a.Name)
		}
		names[a.Name] = true
		if total += a.Size; a.Size < 0 || total > maxTotalBytes {
			return errors.New("release assets are larger than the limit")
		}
	}
	if !names[ChecksumAsset] {
		return fmt.Errorf("release has no %s asset", ChecksumAsset)
	}
	dir := filepath.Join(g.WorkDir, "assets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		return err
	}
	if _, err := g.Run("release", "download", tag, "--repo", g.Repo, "--dir", dir); err != nil {
		return fmt.Errorf("download: %v", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) != len(names) {
		return errors.New("downloaded files differ from the release assets")
	}
	digests := map[string]string{}
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !names[e.Name()] || !info.Mode().IsRegular() {
			return fmt.Errorf("unexpected downloaded file %q", e.Name())
		}
		d, err := fileDigest(filepath.Join(dir, e.Name()))
		if err != nil {
			return err
		}
		digests[e.Name()] = d
	}
	if _, err := g.Run("attestation", "verify", filepath.Join(dir, ChecksumAsset),
		"--repo", g.Repo,
		"--signer-workflow", SignerWorkflow,
		"--source-ref", "refs/tags/"+tag,
		"--source-digest", commit,
		"--deny-self-hosted-runners"); err != nil {
		return fmt.Errorf("%s has no valid attestation from the release workflow for refs/tags/%s at %s: %v", ChecksumAsset, tag, commit, err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, ChecksumAsset))
	if err != nil {
		return err
	}
	return checkSums(raw, digests)
}

// checkSums holds the SHA256SUMS content against the digests of the downloaded
// assets.
func checkSums(raw []byte, digests map[string]string) error {
	listed := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		sum, name, ok := strings.Cut(line, "  ")
		name = strings.TrimPrefix(name, "*")
		if !ok || len(sum) != 64 || !assetName.MatchString(name) || name == ChecksumAsset || listed[name] {
			return fmt.Errorf("%s has an unusable line", ChecksumAsset)
		}
		want, have := digests[name]
		if !have {
			return fmt.Errorf("%s lists %s, which is not a release asset", ChecksumAsset, name)
		}
		if want != sum {
			return fmt.Errorf("asset %s does not match %s", name, ChecksumAsset)
		}
		listed[name] = true
	}
	if sc.Err() != nil {
		return sc.Err()
	}
	var missing []string
	for name := range digests {
		if name != ChecksumAsset && !listed[name] {
			missing = append(missing, name)
		}
	}
	if len(listed) == 0 || len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("assets not covered by %s: %s", ChecksumAsset, strings.Join(missing, ", "))
	}
	return nil
}

func fileDigest(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
