// SPDX-License-Identifier: AGPL-3.0-only

package knowledgegate

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"
)

const approvalUsage = `usage: prufyx-maintainer approval <sign|verify|public-key|keys-digest> [options]
  sign        --pack cncf|community --rule ID --base-pack FILE --head-pack FILE
              --keys FILE --keys-digest sha256:... --identity LOGIN --candidate-id ID
              (--key FILE | --key-stdin) --output FILE [--subject rule]
  verify      --approval FILE --pack cncf|community --rule ID --base-pack FILE --head-pack FILE
              --keys FILE --keys-digest sha256:... [--now RFC3339] [--subject rule]
  public-key  (--key FILE | --key-stdin)
  keys-digest --keys FILE`

// approvalEnv is what the approval commands take from the process; tests
// replace it.
type approvalEnv struct {
	stdin  io.Reader
	now    func() time.Time
	isTerm func(io.Reader) bool
}

func stdinIsTerminal(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// ApprovalMain runs "prufyx-maintainer approval". Exit codes: 0 done (for
// verify: the approval is accepted), 1 verify refused the approval, 2
// rejected input or a refused signing.
func ApprovalMain(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return approvalMain(args, approvalEnv{stdin: stdin, now: time.Now, isTerm: stdinIsTerminal}, DefaultLayout(), stdout, stderr)
}

func approvalMain(args []string, env approvalEnv, layout Layout, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, approvalUsage)
		return 2
	}
	var code int
	var err error
	switch args[0] {
	case "sign":
		code, err = cmdApprovalSign(args[1:], env, layout, stdout)
	case "verify":
		code, err = cmdApprovalVerify(args[1:], env, layout, stdout)
	case "public-key":
		code, err = cmdApprovalPublicKey(args[1:], env, stdout)
	case "keys-digest":
		code, err = cmdApprovalKeysDigest(args[1:], stdout)
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, approvalUsage)
		return 0
	default:
		fmt.Fprintln(stderr, approvalUsage)
		return 2
	}
	if err != nil {
		fmt.Fprintf(stderr, "approval: %s\n", logSafe(err.Error()))
		if code == 0 {
			code = 2
		}
	}
	return code
}

func parseApprovalFlags(f *flag.FlagSet, args []string) error {
	seen := map[string]bool{}
	for _, a := range args {
		if a == "--" {
			break
		}
		if strings.HasPrefix(a, "-") {
			name := strings.SplitN(strings.TrimLeft(a, "-"), "=", 2)[0]
			if seen[name] {
				return fmt.Errorf("option -%s given twice", logSafe(name))
			}
			seen[name] = true
		}
	}
	if err := f.Parse(args); err != nil || f.NArg() != 0 {
		return errors.New("command rejected\n" + approvalUsage)
	}
	return nil
}

// subjectFlags are the flags naming what an approval is for.
type subjectFlags struct {
	subject, pack, rule, basePack, headPack string
	keys, keysDigest                        string
}

func (s *subjectFlags) register(f *flag.FlagSet) {
	f.StringVar(&s.subject, "subject", ApprovalSubjectRule, "what the approval is for: rule")
	f.StringVar(&s.pack, "pack", "", "pack name: cncf or community")
	f.StringVar(&s.rule, "rule", "", "rule id")
	f.StringVar(&s.basePack, "base-pack", "", "the pack file as it is on the base branch")
	f.StringVar(&s.headPack, "head-pack", "", "the pack file as the change proposes it")
	f.StringVar(&s.keys, "keys", "", "the web-approval key file as it is on the base branch")
	f.StringVar(&s.keysDigest, "keys-digest", "", "the pinned digest of the key file")
}

func (s *subjectFlags) load(layout Layout) (ApprovalSubject, ApprovalKeys, error) {
	if s.pack == "" || s.rule == "" || s.basePack == "" || s.headPack == "" || s.keys == "" || s.keysDigest == "" {
		return ApprovalSubject{}, ApprovalKeys{}, errors.New("--pack, --rule, --base-pack, --head-pack, --keys and --keys-digest are required\n" + approvalUsage)
	}
	if s.subject != ApprovalSubjectRule {
		return ApprovalSubject{}, ApprovalKeys{}, fmt.Errorf("--subject %q is not supported (supported: rule)", s.subject)
	}
	var spec *PackSpec
	for i := range layout.Packs {
		if layout.Packs[i].Name == s.pack {
			spec = &layout.Packs[i]
		}
	}
	if spec == nil {
		return ApprovalSubject{}, ApprovalKeys{}, fmt.Errorf("unknown pack %q", s.pack)
	}
	keysRaw, err := readBoundedFile(s.keys, maxApprovalBytes*4)
	if err != nil {
		return ApprovalSubject{}, ApprovalKeys{}, err
	}
	keys, err := LoadApprovalKeys(keysRaw, s.keysDigest)
	if err != nil {
		return ApprovalSubject{}, ApprovalKeys{}, err
	}
	base, err := readBoundedFile(s.basePack, MaxFileBytes)
	if err != nil {
		return ApprovalSubject{}, ApprovalKeys{}, err
	}
	head, err := readBoundedFile(s.headPack, MaxFileBytes)
	if err != nil {
		return ApprovalSubject{}, ApprovalKeys{}, err
	}
	subject, err := RuleApprovalSubject(*spec, base, head, s.rule)
	if err != nil {
		return ApprovalSubject{}, ApprovalKeys{}, err
	}
	return subject, keys, nil
}

// keyFlags select where the private key comes from.
type keyFlags struct {
	file  string
	stdin bool
}

func (k *keyFlags) register(f *flag.FlagSet) {
	f.StringVar(&k.file, "key", "", "private key file (mode 0600 or stricter, owned by you)")
	f.BoolVar(&k.stdin, "key-stdin", false, "read the private key from standard input (a pipe, never a terminal)")
}

// load reads and parses the private key. The caller wipes it.
func (k keyFlags) load(env approvalEnv) (ed25519.PrivateKey, error) {
	if (k.file == "") == !k.stdin {
		return nil, errors.New("give exactly one of --key FILE and --key-stdin")
	}
	var raw []byte
	var err error
	if k.stdin {
		if env.isTerm(env.stdin) {
			return nil, errors.New("--key-stdin reads a pipe, not a terminal (typed keys would be echoed); pipe the key in")
		}
		raw, err = io.ReadAll(io.LimitReader(env.stdin, MaxApprovalKeyBytes+1))
		if err != nil {
			wipe(raw)
			return nil, errors.New("the key cannot be read from standard input")
		}
	} else {
		if raw, err = readApprovalKeyFile(k.file); err != nil {
			return nil, err
		}
	}
	defer wipe(raw)
	return ParseApprovalPrivateKey(raw)
}

func cmdApprovalSign(args []string, env approvalEnv, layout Layout, stdout io.Writer) (int, error) {
	var s subjectFlags
	var k keyFlags
	var identity, candidateID, output string
	f := flag.NewFlagSet("approval sign", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	s.register(f)
	k.register(f)
	f.StringVar(&identity, "identity", "", "the owner's login, as pinned in the key file")
	f.StringVar(&candidateID, "candidate-id", "", "a reference for the change, for example its pull request")
	f.StringVar(&output, "output", "", "new approval file to write")
	if err := parseApprovalFlags(f, args); err != nil {
		return 2, err
	}
	if identity == "" || candidateID == "" || output == "" {
		return 2, errors.New("--identity, --candidate-id and --output are required\n" + approvalUsage)
	}
	if _, err := os.Lstat(output); err == nil {
		return 2, fmt.Errorf("%s already exists; remove the old approval first", output)
	}
	subject, keys, err := s.load(layout)
	if err != nil {
		return 2, err
	}
	key, err := k.load(env)
	if err != nil {
		return 2, err
	}
	keyID := ApprovalKeyID(key.Public().(ed25519.PublicKey))
	raw, rec, err := SignApproval(SignApprovalOptions{Subject: subject, CandidateID: candidateID, Identity: identity, Keys: keys, Key: key, Now: env.now()})
	wipe(key)
	if err != nil {
		return 2, err
	}
	if err := writeNewFile(output, raw); err != nil {
		return 2, err
	}
	var pinned ApprovalKey
	for _, pk := range keys.Keys {
		if pk.KeyID == keyID {
			pinned = pk
		}
	}
	fmt.Fprintf(stdout, "approval written: %s\n", logSafe(output))
	printApproval(stdout, rec, pinned)
	return 0, nil
}

func printApproval(w io.Writer, rec ApprovalRecord, key ApprovalKey) {
	fmt.Fprintf(w, "  subject    rule %s/%s\n", rec.Pack, rec.RuleID)
	fmt.Fprintf(w, "  base       %s\n", rec.BaseDigest)
	fmt.Fprintf(w, "  candidate  %s\n", rec.CandidateDigest)
	fmt.Fprintf(w, "  identity   %s (candidate %s)\n", rec.Identity, rec.CandidateID)
	fmt.Fprintf(w, "  key        %s\n", key.KeyID)
	fmt.Fprintf(w, "  decided    %s, accepted until %s\n", rec.DecidedAt, ApprovalUsableUntil(rec, key))
}

// writeNewFile creates path (never replacing anything, never through a
// link) with the approval's bytes.
func writeNewFile(path string, raw []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return fmt.Errorf("cannot create %s: %w", path, err)
	}
	_, werr := f.Write(raw)
	if werr == nil {
		werr = f.Sync()
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = os.Remove(path)
		return werr
	}
	return nil
}

func cmdApprovalVerify(args []string, env approvalEnv, layout Layout, stdout io.Writer) (int, error) {
	var s subjectFlags
	var approval, now string
	f := flag.NewFlagSet("approval verify", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	s.register(f)
	f.StringVar(&approval, "approval", "", "the approval file")
	f.StringVar(&now, "now", "", "the clock, RFC 3339 UTC (default: now)")
	if err := parseApprovalFlags(f, args); err != nil {
		return 2, err
	}
	if approval == "" {
		return 2, errors.New("--approval is required\n" + approvalUsage)
	}
	at := env.now()
	if now != "" {
		var err error
		if at, err = time.Parse(time.RFC3339, now); err != nil || !strings.HasSuffix(now, "Z") {
			return 2, errors.New("--now must be RFC 3339 UTC")
		}
	}
	subject, keys, err := s.load(layout)
	if err != nil {
		return 2, err
	}
	raw, err := readBoundedFile(approval, maxApprovalBytes+1)
	if err != nil {
		return 2, err
	}
	if err := VerifyApprovalSubject(raw, keys, subject, at); err != nil {
		fmt.Fprintf(stdout, "approval REFUSED: %s\n", logSafe(err.Error()))
		return 1, nil
	}
	var accepted ApprovalEnvelope
	if err := strictDecode([]byte(strings.TrimSuffix(string(raw), "\n")), &accepted); err != nil {
		return 2, err
	}
	var key ApprovalKey
	for _, pk := range keys.Keys {
		if pk.KeyID == accepted.KeyID {
			key = pk
		}
	}
	fmt.Fprintf(stdout, "approval OK: %s\n", logSafe(approval))
	printApproval(stdout, accepted.Record, key)
	return 0, nil
}

func cmdApprovalPublicKey(args []string, env approvalEnv, stdout io.Writer) (int, error) {
	var k keyFlags
	f := flag.NewFlagSet("approval public-key", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	k.register(f)
	if err := parseApprovalFlags(f, args); err != nil {
		return 2, err
	}
	key, err := k.load(env)
	if err != nil {
		return 2, err
	}
	pub := key.Public().(ed25519.PublicKey)
	wipe(key)
	out, err := json.Marshal(struct {
		KeyID     string `json:"keyId"`
		PublicKey string `json:"publicKey"`
	}{ApprovalKeyID(pub), hex.EncodeToString(pub)})
	if err != nil {
		return 2, err
	}
	fmt.Fprintln(stdout, string(out))
	return 0, nil
}

func cmdApprovalKeysDigest(args []string, stdout io.Writer) (int, error) {
	var keys string
	f := flag.NewFlagSet("approval keys-digest", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	f.StringVar(&keys, "keys", "", "the web-approval key file")
	if err := parseApprovalFlags(f, args); err != nil {
		return 2, err
	}
	if keys == "" {
		return 2, errors.New("--keys is required\n" + approvalUsage)
	}
	raw, err := readBoundedFile(keys, maxApprovalBytes*4)
	if err != nil {
		return 2, err
	}
	if _, err := ParseApprovalKeys(raw); err != nil {
		return 2, err
	}
	fmt.Fprintln(stdout, ApprovalKeysDigest(raw))
	return 0, nil
}
