// SPDX-License-Identifier: AGPL-3.0-only

package communityapp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/prufyx/prufyx/cli/internal/knowledge"
	"github.com/prufyx/prufyx/cli/internal/knowledgecheck"
	"github.com/prufyx/prufyx/cli/internal/knowledgefetch"
	"github.com/prufyx/prufyx/cli/internal/knowledgereleaseplan"
)

const updateUsage = "Usage: prufyx db update (--source HTTPS_URL [--profile cert-manager|cncf|cncf-projects|spiffe-x509-svid|cloudevents-structured-json|tikv-gcp-v2-wif-backup] [--expected-revision REVISION] [--expected-bundle-digest SHA256] | --release-plan LOCAL_FILE) --package-out FILE --db-root DIR [--bootstrap-root FILE --bootstrap-root-digest SHA256] [--format human|json]"

type knowledgeUpdateOutput struct {
	APIVersion             string                   `json:"apiVersion"`
	Status                 string                   `json:"status"`
	Profile                string                   `json:"profile"`
	NetworkAttempted       bool                     `json:"networkAttempted"`
	TransferCompleted      bool                     `json:"transferCompleted"`
	PackageRetained        bool                     `json:"packageRetained"`
	PartialCleanupRequired bool                     `json:"partialCleanupRequired"`
	PackageDigest          string                   `json:"packageDigest,omitempty"`
	ImportReceipt          *knowledge.ImportReceipt `json:"importReceipt,omitempty"`
	Rejection              *rejectedImportOutput    `json:"rejection,omitempty"`
	ReasonCode             string                   `json:"reasonCode"`
	NextAction             string                   `json:"nextAction"`
}

func (r runtime) databaseUpdate(ctx context.Context, args []string) int {
	return r.databaseUpdateWithFetches(ctx, args, knowledgefetch.Fetch, knowledgefetch.FetchPerProject)
}

// The injected function is a test seam. Production has one fixed transport;
// private check inputs and environment-derived clients never enter this API.
func (r runtime) databaseUpdateWithFetch(ctx context.Context, args []string, fetch func(context.Context, string) ([]byte, error)) int {
	return r.databaseUpdateWithFetches(ctx, args, fetch, fetch)
}

// databaseUpdateWithFetches selects the transport bound by profile: a
// per-project CNCF package may be larger than a single-target package.
func (r runtime) databaseUpdateWithFetches(ctx context.Context, args []string, fetch, fetchPerProject func(context.Context, string) ([]byte, error)) int {
	if hasHelp(args) {
		fmt.Fprintln(r.stdout, updateUsage+"\n\nExplicitly fetch a complete package, retain it privately, then verify and import\nlocally. A release plan supplies unsigned routing and exact verification assertions;\nit never supplies bootstrap trust. The output must be new, outside the store, in\nan existing 0700 directory. Obtain the initial root and its identity independently.\nNo official Prufyx feed or root is configured. Checks, replay, import and status\nremain offline.")
		return ExitOK
	}
	fs := flag.NewFlagSet("db update", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	source := fs.String("source", "", "explicit HTTPS complete-package URL")
	releasePlan := fs.String("release-plan", "", "local canonical unsigned routing and assertion plan")
	packageOut := fs.String("package-out", "", "new retained package file in a private directory outside the store")
	dbRoot := fs.String("db-root", "", "private knowledge store root")
	profile := fs.String("profile", "cert-manager", "cert-manager, cncf, cncf-projects, spiffe-x509-svid, cloudevents-structured-json, or tikv-gcp-v2-wif-backup in separate directories")
	bootstrapRoot := fs.String("bootstrap-root", "", "independently provisioned initial TUF root")
	bootstrapDigest := fs.String("bootstrap-root-digest", "", "exact initial root SHA-256")
	expectedRevision := fs.String("expected-revision", "", "optional exact semantic revision assertion")
	expectedBundle := fs.String("expected-bundle-digest", "", "optional exact target SHA-256 assertion")
	format := fs.String("format", "human", "human or json")
	if duplicateFlags(args) || fs.Parse(args) != nil || fs.NArg() != 0 || *packageOut == "" || *dbRoot == "" || (*format != "human" && *format != "json") || (*bootstrapRoot == "") != (*bootstrapDigest == "") {
		return r.usage("invalid database update arguments; use --help")
	}
	planMode := *releasePlan != ""
	if (planMode && anyFlagProvided(args, "source", "profile", "expected-revision", "expected-bundle-digest")) || (!planMode && (knowledgefetch.ValidateSource(*source) != nil || !validKnowledgeProfile(*profile))) {
		return r.usage("invalid database update arguments; use --help")
	}
	req := knowledge.ImportRequest{
		StoreRoot: *dbRoot, BootstrapRootPath: *bootstrapRoot, BootstrapRootDigest: *bootstrapDigest,
		ExpectedRevision: *expectedRevision, ExpectedBundleDigest: *expectedBundle,
	}
	if planMode {
		plan, err := knowledgereleaseplan.Read(*releasePlan)
		if err != nil {
			return r.usage("invalid database release plan; use --help")
		}
		assertions := plan.VerificationAssertions()
		*source, *profile = plan.Package.URL, plan.Profile
		req.ExpectedPackageDigest = plan.Package.Digest
		req.ExpectedRevision = plan.Target.Revision
		req.ExpectedBundleDigest = plan.Target.Digest
		req.ExpectedVerification = &assertions
	}
	if err := knowledge.ValidateImportAssertions(req); err != nil {
		return r.knowledgeError("invalid local database update assertions", err)
	}
	parent, name, packagePath, err := reserveKnowledgeDownload(*packageOut, *dbRoot)
	if err != nil {
		return r.fail("package output requires a new file outside the store in an existing private 0700 directory", ExitUsage)
	}
	defer parent.Close()
	f, err := parent.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return r.fail("package output cannot be created; use a new private file", ExitUsage)
	}
	retained := false
	cleanupAttempted := false
	defer func() {
		f.Close()
		if !retained && !cleanupAttempted {
			parent.Remove(name)
		}
	}()
	output := knowledgeUpdateOutput{
		APIVersion: "prufyx.io/knowledge-update/v1alpha1", Status: "REJECTED", Profile: *profile,
		ReasonCode: "KNOWLEDGE_DOWNLOAD_FAILED",
		NextAction: "verify the package source and retry with a new output file; no import was attempted",
	}
	var raw []byte
	fileInfo, fileInfoErr := f.Stat()
	finish := func(code int) int {
		if !retained {
			f.Close()
			cleanupAttempted = true
			info, err := parent.Lstat(name)
			if err == nil && (fileInfo == nil || !os.SameFile(info, fileInfo)) {
				err = knowledge.ErrIntegrity
			} else if err == nil {
				err = parent.Remove(name)
			}
			if err != nil && !os.IsNotExist(err) {
				output.PartialCleanupRequired = true
				output.ReasonCode = "KNOWLEDGE_PARTIAL_PACKAGE_CLEANUP_REQUIRED"
				output.NextAction = "inspect the untrusted partial or replaced output locally before retrying; no import was attempted"
				code = ExitIntegrity
			}
		} else if !retainedKnowledgeDownloadMatches(parent, name, fileInfo, raw) {
			output.PackageRetained = false
			output.Status = "RETENTION_INTEGRITY_FAILURE"
			output.ReasonCode = "KNOWLEDGE_RETAINED_PACKAGE_CHANGED"
			output.NextAction = "inspect the output directory and db status; the import receipt, if present, remains authoritative for selection changes; recover only with the exact original package digest"
			code = ExitIntegrity
		}
		return r.writeKnowledgeUpdate(output, *format, code)
	}
	if err := f.Chmod(0o600); err != nil {
		output.ReasonCode = "KNOWLEDGE_PACKAGE_PERMISSIONS_FAILED"
		return finish(ExitIntegrity)
	}
	if fileInfoErr != nil {
		output.ReasonCode = "KNOWLEDGE_PACKAGE_IDENTITY_FAILED"
		return finish(ExitIntegrity)
	}
	// Creating the reserved file also reveals a not-yet-existing store alias
	// on case-insensitive or normalization-insensitive filesystems.
	if info, err := os.Stat(*dbRoot); err == nil && !info.IsDir() {
		output.ReasonCode = "KNOWLEDGE_OUTPUT_ALIASES_STORE"
		return finish(ExitUsage)
	}
	output.NetworkAttempted = true
	if *profile == "cncf-projects" {
		fetch = fetchPerProject
	}
	raw, err = fetch(ctx, *source)
	if err != nil {
		if errors.Is(err, knowledgefetch.ErrOversized) {
			output.ReasonCode = "KNOWLEDGE_DOWNLOAD_TOO_LARGE"
		}
		return finish(ExitIntegrity)
	}
	output.TransferCompleted = true
	if _, err = f.Write(raw); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		var directory *os.File
		directory, err = parent.Open(".")
		if err == nil {
			err = directory.Sync()
			if closeErr := directory.Close(); err == nil {
				err = closeErr
			}
		}
	}
	if err != nil {
		output.ReasonCode = "KNOWLEDGE_PACKAGE_RETENTION_FAILED"
		output.NextAction = "check the private output directory and retry; no import was attempted"
		return finish(ExitIntegrity)
	}
	// Keep the exact bytes even on semantic rejection: import may have advanced
	// durable trust, and recovery must not depend on a mutable remote URL.
	retained = true
	output.PackageRetained = true
	sum := sha256.Sum256(raw)
	output.PackageDigest = "sha256:" + hex.EncodeToString(sum[:])
	if !retainedKnowledgeDownloadMatches(parent, name, fileInfo, raw) {
		return finish(ExitIntegrity)
	}
	req.PackagePath = packagePath
	if req.ExpectedPackageDigest == "" {
		req.ExpectedPackageDigest = output.PackageDigest
	}
	var receipt knowledge.ImportReceipt
	if *profile == "cncf" {
		receipt, err = knowledge.ImportConstraints(req)
	} else if *profile == "cncf-projects" {
		receipt, err = knowledge.ImportConstraintsProjects(req)
	} else if *profile == "spiffe-x509-svid" {
		receipt, err = knowledge.ImportSPIFFEX509SVID(req)
	} else if *profile == "cloudevents-structured-json" {
		receipt, err = knowledge.ImportCloudEventsStructuredJSON(req)
	} else if *profile == "tikv-gcp-v2-wif-backup" {
		receipt, err = knowledge.ImportTiKVGCPV2WIFBackup(req)
	} else {
		receipt, err = knowledge.Import(req, knowledgecheck.AdmitBundle)
	}
	if err != nil {
		output.ReasonCode = "KNOWLEDGE_PACKAGE_IMPORT_REJECTED"
		output.NextAction = "retain the downloaded package; inspect db status for this profile and follow local db import recovery instructions"
		if errors.Is(err, knowledge.ErrLayout) {
			output.ReasonCode = "KNOWLEDGE_LAYOUT_MISMATCH"
			output.NextAction = knowledgeLayoutNextAction
		}
		if receipt.APIVersion != "" {
			rejection := rejectedKnowledgeImport(receipt, err, *profile)
			output.Rejection = &rejection
			output.NextAction = rejection.NextAction + "; use db import with the retained local package, not another download"
		}
		code := ExitIntegrity
		if errors.Is(err, knowledge.ErrInvalid) {
			code = ExitUsage
		}
		return finish(code)
	}
	output.Status = receipt.Status
	output.ImportReceipt = &receipt
	output.ReasonCode = "KNOWLEDGE_PACKAGE_VERIFIED_AND_IMPORTED"
	output.NextAction = "evaluate local inputs using the selected store; retain package and report identities for replay"
	return finish(ExitOK)
}

// Resolve the output parent once and use a directory descriptor for creation
// and cleanup. This is a retained public-data file, never a store member.
func reserveKnowledgeDownload(output, store string) (*os.Root, string, string, error) {
	abs, err := filepath.Abs(output)
	if err != nil {
		return nil, "", "", err
	}
	parentPath, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, "", "", err
	}
	storeAbs, err := filepath.Abs(store)
	if err != nil {
		return nil, "", "", err
	}
	storePath, err := filepath.EvalSymlinks(storeAbs)
	if os.IsNotExist(err) {
		var storeParent string
		storeParent, err = filepath.EvalSymlinks(filepath.Dir(storeAbs))
		storePath = filepath.Join(storeParent, filepath.Base(storeAbs))
	}
	if err != nil {
		return nil, "", "", err
	}
	packagePath := filepath.Join(parentPath, filepath.Base(abs))
	rel, err := filepath.Rel(storePath, packagePath)
	if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return nil, "", "", knowledge.ErrInvalid
	}
	// Path spelling is not identity on all supported filesystems. Compare
	// existing ancestors physically, including case/Unicode aliases.
	if storeInfo, err := os.Stat(storePath); err == nil {
		if !storeInfo.IsDir() {
			return nil, "", "", knowledge.ErrInvalid
		}
		for ancestor := parentPath; ; ancestor = filepath.Dir(ancestor) {
			info, err := os.Stat(ancestor)
			if err != nil || os.SameFile(info, storeInfo) {
				return nil, "", "", knowledge.ErrInvalid
			}
			if filepath.Dir(ancestor) == ancestor {
				break
			}
		}
	} else if !os.IsNotExist(err) {
		return nil, "", "", knowledge.ErrInvalid
	}
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, "", "", err
	}
	info, err := root.Stat(".")
	if err != nil {
		root.Close()
		return nil, "", "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm() != 0o700 || !ok || stat.Uid != uint32(os.Geteuid()) {
		root.Close()
		return nil, "", "", knowledge.ErrInvalid
	}
	return root, filepath.Base(abs), packagePath, nil
}

func retainedKnowledgeDownloadMatches(parent *os.Root, name string, original os.FileInfo, raw []byte) bool {
	if original == nil {
		return false
	}
	parentInfo, err := parent.Stat(".")
	if err != nil || parentInfo.Mode().Perm() != 0o700 {
		return false
	}
	pathInfo, err := os.Stat(parent.Name())
	if err != nil || !os.SameFile(parentInfo, pathInfo) {
		return false
	}
	f, err := parent.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 || !os.SameFile(info, original) || info.Size() != int64(len(raw)) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 || stat.Uid != uint32(os.Geteuid()) {
		return false
	}
	retained, err := io.ReadAll(io.LimitReader(f, int64(len(raw))+1))
	if err != nil || !bytes.Equal(retained, raw) {
		return false
	}
	after, err := parent.Lstat(name)
	if err != nil || !os.SameFile(info, after) || !after.Mode().IsRegular() || after.Mode().Perm() != 0o600 || after.Size() != info.Size() || !after.ModTime().Equal(info.ModTime()) {
		return false
	}
	finalStat, ok := after.Sys().(*syscall.Stat_t)
	return ok && finalStat.Nlink == 1 && finalStat.Uid == uint32(os.Geteuid())
}

func (r runtime) writeKnowledgeUpdate(output knowledgeUpdateOutput, format string, code int) int {
	if format == "json" {
		return r.writeJSON(output, code)
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, "knowledge update: %s\nprofile: %s\nnetwork attempted: %t\ntransfer completed: %t\npackage retained: %t\npartial cleanup required: %t\npackage digest: %s\nreason: %s\nnext action: %s\n", output.Status, output.Profile, output.NetworkAttempted, output.TransferCompleted, output.PackageRetained, output.PartialCleanupRequired, output.PackageDigest, output.ReasonCode, output.NextAction)
	if receipt := output.ImportReceipt; receipt != nil {
		fmt.Fprintf(&b, "revision: %s\npurpose: %s\ntrust source: %s\nbundle digest: %s\ntrust receipt digest: %s\n", receipt.TrustReceipt.KnowledgeRevision, receipt.TrustReceipt.Purpose, receipt.TrustReceipt.TrustSource, receipt.TrustReceipt.TargetDigest, receipt.TrustReceiptDigest)
		if len(receipt.ProjectTargets) > 0 {
			fmt.Fprintf(&b, "project targets: %d\n", len(receipt.ProjectTargets))
		}
		if receipt.TrustReceipt.Purpose == "synthetic_test_only" {
			fmt.Fprintln(&b, "authority: synthetic test knowledge only; no official Prufyx trust root or compatibility proof")
		}
	}
	if rejection := output.Rejection; rejection != nil {
		fmt.Fprintf(&b, "trust state advanced: %t\nselection changed: %t\ntrust state digest: %s\nimport rejection: %s\n", rejection.TrustStateAdvanced, rejection.SelectionChanged, rejection.TrustStateDigest, rejection.ReasonCode)
	}
	if n, err := r.stdout.Write(b.Bytes()); err != nil || n != b.Len() {
		return ExitIntegrity
	}
	return code
}
