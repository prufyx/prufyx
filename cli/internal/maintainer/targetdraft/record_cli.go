// SPDX-License-Identifier: AGPL-3.0-only

package targetdraft

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"strings"
	"syscall"
)

const recordEnvelopeSchema = "prufyx.io/target-draft-record/v1"
const maxRecordEnvelope = 32 << 20

type recordEnvelope struct {
	Schema      string `json:"schema"`
	Recipe      string `json:"recipe"`
	Rules       string `json:"rules"`
	FactsBundle string `json:"factsBundle"`
	Target      string `json:"target"`
	Report      string `json:"report"`
	TableRow    string `json:"tableRow"`
	Changelog   string `json:"changelog"`
}

// runRecord records a local, replayable draft; it grants no publication authority.
func runRecord(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("target-draft record", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	dir, slug, name, repo, tags := fs.String("dir", "", ""), fs.String("slug", "", ""), fs.String("name", "", ""), fs.String("repo", "", ""), fs.String("tags", "", "")
	expectedTarget, expectedRow, rules := fs.String("expected-target", "", ""), fs.String("expected-row", "", ""), fs.String("rules", "", "")
	catalog, component, factProject := fs.String("catalog", "", ""), fs.String("component", "", ""), fs.String("fact-project", "", "")
	strictWindow, collapse := fs.Bool("strict-window", false, ""), fs.Bool("collapse-directories", false, "")
	rangeTags := fs.String("range-check-tags", "", "")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *dir == "" || *slug == "" || *name == "" || *repo == "" || *tags == "" || *expectedTarget == "" || *expectedRow == "" {
		return errors.New("invalid target-draft record arguments")
	}
	if err := regularDir(*dir); err != nil {
		return err
	}
	target, err := readRecordFile(*expectedTarget, maxOutputBytes)
	if err != nil {
		return err
	}
	row, err := readRecordFile(*expectedRow, maxOutputBytes)
	if err != nil {
		return err
	}
	in := Input{Slug: *slug, Name: *name, Repo: *repo, Tags: splitRecordTags(*tags), Catalog: *catalog, Component: *component, FactProject: *factProject, StrictWindow: *strictWindow, CollapseDirectories: *collapse, RangeCheckTags: splitRecordTags(*rangeTags)}
	if *rules != "" {
		raw, err := readRecordFile(*rules, MaxRecipeBytes)
		if err != nil {
			return err
		}
		in.Rules, err = ParseRules(raw)
		if err != nil {
			return err
		}
	}
	recorded, err := RecordDraft(in, GitSource{Dir: *dir}, target, row)
	if err != nil {
		return err
	}
	env := recordEnvelope{Schema: recordEnvelopeSchema, Recipe: recordB64(recorded.Recipe), Rules: recordB64(recorded.Rules), FactsBundle: recordB64(recorded.FactsBundle), Target: recordB64(recorded.Target), Report: recordB64(recorded.Report), TableRow: recordB64(recorded.TableRow), Changelog: recordB64(recorded.Changelog)}
	raw, err := json.Marshal(env)
	if err != nil || len(raw) > maxRecordEnvelope {
		return errors.New("record envelope refused")
	}
	_, err = stdout.Write(append(raw, '\n'))
	return err
}

func recordB64(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(raw)
}
func splitRecordTags(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func regularDir(path string) error {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("record directory refused")
	}
	return nil
}

func readRecordFile(path string, limit int) ([]byte, error) {
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("record input refused")
	}
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, errors.New("record input refused")
	}
	defer f.Close()
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		return nil, errors.New("record input changed")
	}
	var out bytes.Buffer
	if _, err := io.Copy(&out, io.LimitReader(f, int64(limit)+1)); err != nil || out.Len() > limit {
		return nil, errors.New("record input refused")
	}
	return out.Bytes(), nil
}
