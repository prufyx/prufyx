// SPDX-License-Identifier: AGPL-3.0-only

package knowledgepacket

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Run is the knowledge-packet command. It writes both outputs only after the
// whole packet is built; on any error nothing is written.
func Run(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("knowledge-packet", flag.ContinueOnError)
	fs.SetOutput(stderr)
	repoDir := fs.String("repo", ".", "local git repository with full history")
	base := fs.String("base", "", "source commit of the last published revision")
	head := fs.String("head", "", "candidate source commit")
	prev := fs.Int("previous-revision", -1, "last published revision number")
	input := fs.String("input", "", "pull request input JSON (schema "+InputSchema+")")
	outJSON := fs.String("out-json", "", "packet JSON output path")
	outMD := fs.String("out-md", "", "markdown summary output path")
	ids := fs.String("trusted-user-ids", "", "comma-separated numeric user ids whose gate and review markers count")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %v", fs.Args())
	}
	if *base == "" || *head == "" || *input == "" || *outJSON == "" || *outMD == "" || *prev < 0 {
		return errors.New("--base, --head, --previous-revision, --input, --out-json, --out-md and --trusted-user-ids are required")
	}
	trusted, err := parseIDs(*ids)
	if err != nil {
		return err
	}
	f, err := os.Open(*input)
	if err != nil {
		return err
	}
	defer f.Close()
	in, err := ParseInput(f)
	if err != nil {
		return err
	}
	p, err := Build(context.Background(), Options{Repo: *repoDir, Base: *base, Head: *head, PreviousRevision: *prev, Input: *in, TrustedUserIDs: trusted})
	if err != nil {
		return err
	}
	js, err := p.JSON()
	if err != nil {
		return err
	}
	if err := writeFile(*outJSON, js); err != nil {
		return err
	}
	if err := writeFile(*outMD, []byte(p.Markdown())); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "knowledge-packet: entries=%d unverified=%d nonData=%d trustPath=%d entriesDigest=%s packetDigest=%s\n",
		len(p.Entries), p.Summary.Unverified, p.Summary.NonData, p.Summary.TrustPath, p.EntriesDigest, p.PacketDigest)
	return nil
}

func writeFile(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".knowledge-packet-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func parseIDs(s string) ([]int64, error) {
	var out []int64
	for _, f := range strings.Split(s, ",") {
		id, err := strconv.ParseInt(strings.TrimSpace(f), 10, 64)
		if err != nil || id <= 0 {
			return nil, fmt.Errorf("--trusted-user-ids: %q is not a positive numeric user id", f)
		}
		out = append(out, id)
	}
	return out, nil
}
