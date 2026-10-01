// SPDX-License-Identifier: AGPL-3.0-only

// Package sourcecapture performs bounded, maintainer-only capture of declared
// immutable public GitHub source bytes for later offline verification.
package sourcecapture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

const (
	Schema             = "prufyx.io/private-public-source-capture-request/v1"
	ReceiptSchema      = "prufyx.io/private-public-source-capture-receipt/v1"
	Authority          = "DECLARED_PUBLIC_SOURCE_REQUESTS_NOT_RULE_OR_RUNTIME_PROOF"
	LocalAuthority     = "LOCAL_CAPTURED_PUBLIC_BYTES_NOT_RULE_OR_RUNTIME_PROOF"
	MaxRequestBytes    = 256 * 1024
	MaxLogicalRequests = 64
	MaxUniqueBytes     = 16 * 1024 * 1024
	MaxObjectBytes     = 4 * 1024 * 1024
	MaxHeaderBytes     = 16 * 1024
	MaxHeaderLine      = 4096
	MaxHeaders         = 64
	MaxReceiptBytes    = 256 * 1024
	PerSourceTimeout   = 30 * time.Second
	AttemptTimeout     = 120 * time.Second
	RawHost            = "raw.githubusercontent.com"
	RawPort            = "443"
	UserAgent          = "prufyx-private-source-capture/1"
)

var (
	errRejected  = errors.New("public source capture rejected")
	rawPath      = regexp.MustCompile(`^/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/[0-9a-f]{40}/(?:[A-Za-z0-9._+.-]+/)*[A-Za-z0-9._+.-]+$`)
	headerName   = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	contentBytes = regexp.MustCompile(`^[0-9]{1,7}$`)
	chunkBytes   = regexp.MustCompile(`^[0-9A-Fa-f]{1,8}$`)
)

// Error deliberately excludes caller values, paths, and response bodies.
var Error = errRejected

// FetchResult is the minimized transport result accepted by Capture.
type FetchResult struct {
	Kind       string
	StatusCode int
	Body       []byte
}

// Fetcher receives only a validated raw.githubusercontent.com request path.
// Implementations must respect context cancellation. Tests inject this seam;
// production uses FixedHTTPSFetcher.
type Fetcher interface {
	Fetch(context.Context, string) FetchResult
}

type FetchFunc func(context.Context, string) FetchResult

func (function FetchFunc) Fetch(ctx context.Context, path string) FetchResult {
	return function(ctx, path)
}

// FixedHTTPSFetcher speaks bounded HTTP/1.1 to one fixed TLS host. It has no
// proxy, redirect, retry, cookie, auth, endpoint override, or response decode.
type FixedHTTPSFetcher struct{}

func (FixedHTTPSFetcher) Fetch(ctx context.Context, path string) FetchResult {
	dialer := net.Dialer{Timeout: 10 * time.Second}
	return fetchFixedHTTPS(ctx, path, dialer.DialContext, func(raw net.Conn) handshakingConn {
		return tls.Client(raw, &tls.Config{ServerName: RawHost, MinVersion: tls.VersionTLS12})
	})
}

type handshakingConn interface {
	net.Conn
	HandshakeContext(context.Context) error
}

func fetchFixedHTTPS(
	ctx context.Context,
	path string,
	dial func(context.Context, string, string) (net.Conn, error),
	wrapTLS func(net.Conn) handshakingConn,
) FetchResult {
	if !rawPath.MatchString(path) {
		return FetchResult{Kind: "RESPONSE_REJECTED"}
	}
	for _, variable := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE"} {
		if os.Getenv(variable) != "" {
			return FetchResult{Kind: "TRANSPORT_FAILURE"}
		}
	}
	raw, err := dial(ctx, "tcp", net.JoinHostPort(RawHost, RawPort))
	if err != nil {
		return transportFailure(ctx, err)
	}
	stopCancelClose := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer func() {
		stopCancelClose()
		_ = raw.Close()
	}()
	tlsConnection := wrapTLS(raw)
	if deadline, ok := ctx.Deadline(); ok {
		_ = tlsConnection.SetDeadline(deadline)
	}
	if err = tlsConnection.HandshakeContext(ctx); err != nil {
		return transportFailure(ctx, err)
	}
	request := "GET " + path + " HTTP/1.1\r\nHost: " + RawHost + "\r\nUser-Agent: " + UserAgent + "\r\nAccept: application/octet-stream\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n"
	if _, err = io.WriteString(tlsConnection, request); err != nil {
		return transportFailure(ctx, err)
	}
	status, headers, reader, err := readHeader(tlsConnection)
	if err != nil {
		if ctx.Err() != nil {
			return transportFailure(ctx, err)
		}
		if isTimeout(ctx, err) {
			return FetchResult{Kind: "TRANSPORT_TIMEOUT"}
		}
		if _, ok := err.(net.Error); ok {
			return FetchResult{Kind: "TRANSPORT_FAILURE"}
		}
		return FetchResult{Kind: "RESPONSE_REJECTED"}
	}
	if status != 200 {
		if status < 100 || status > 599 {
			return FetchResult{Kind: "TRANSPORT_FAILURE"}
		}
		return FetchResult{Kind: "HTTP_STATUS", StatusCode: status}
	}
	body, err := readBody(reader, headers)
	if err != nil {
		if ctx.Err() != nil {
			return transportFailure(ctx, err)
		}
		if isTimeout(ctx, err) {
			return FetchResult{Kind: "TRANSPORT_TIMEOUT"}
		}
		if _, ok := err.(net.Error); ok {
			return FetchResult{Kind: "TRANSPORT_FAILURE"}
		}
		return FetchResult{Kind: "RESPONSE_REJECTED"}
	}
	if len(body) < 1 || len(body) > MaxObjectBytes {
		return FetchResult{Kind: "RESPONSE_REJECTED"}
	}
	return FetchResult{Kind: "HTTP_200", StatusCode: 200, Body: body}
}

func isTimeout(ctx context.Context, err error) bool {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netError net.Error
	return errors.As(err, &netError) && netError.Timeout()
}

func transportFailure(ctx context.Context, err error) FetchResult {
	if isTimeout(ctx, err) {
		return FetchResult{Kind: "TRANSPORT_TIMEOUT"}
	}
	return FetchResult{Kind: "TRANSPORT_FAILURE"}
}

type wireReader struct {
	reader io.Reader
	buffer []byte
}

func (reader *wireReader) more(maximum int) error {
	if maximum < 1 {
		return errRejected
	}
	chunk := make([]byte, maximum)
	count, err := reader.reader.Read(chunk)
	if count > 0 {
		reader.buffer = append(reader.buffer, chunk[:count]...)
	}
	if count == 0 {
		if err == nil {
			return io.ErrNoProgress
		}
		return err
	}
	return nil
}

func (reader *wireReader) exact(amount int) ([]byte, error) {
	for len(reader.buffer) < amount {
		if err := reader.more(amount - len(reader.buffer)); err != nil {
			return nil, err
		}
	}
	result := append([]byte(nil), reader.buffer[:amount]...)
	reader.buffer = reader.buffer[amount:]
	return result, nil
}

func (reader *wireReader) line(maximum int) ([]byte, error) {
	for {
		if marker := bytes.Index(reader.buffer, []byte("\r\n")); marker >= 0 {
			if marker > maximum {
				return nil, errRejected
			}
			result := append([]byte(nil), reader.buffer[:marker]...)
			reader.buffer = reader.buffer[marker+2:]
			return result, nil
		}
		if len(reader.buffer) < maximum {
			if err := reader.more(maximum - len(reader.buffer)); err != nil {
				return nil, err
			}
			continue
		}
		if len(reader.buffer) == maximum {
			if err := reader.more(1); err != nil {
				return nil, err
			}
			continue
		}
		if reader.buffer[maximum] != '\r' {
			return nil, errRejected
		}
		if len(reader.buffer) == maximum+1 {
			if err := reader.more(1); err != nil {
				return nil, err
			}
			continue
		}
		if string(reader.buffer[maximum:maximum+2]) != "\r\n" {
			return nil, errRejected
		}
		result := append([]byte(nil), reader.buffer[:maximum]...)
		reader.buffer = reader.buffer[maximum+2:]
		return result, nil
	}
}

func readHeader(input io.Reader) (int, map[string]string, *wireReader, error) {
	reader := &wireReader{reader: input}
	total := 0
	lineWithinTotal := func() ([]byte, error) {
		remaining := MaxHeaderBytes - total
		if remaining < 2 {
			return nil, errRejected
		}
		maximum := min(MaxHeaderLine, remaining-2)
		for {
			if marker := bytes.Index(reader.buffer, []byte("\r\n")); marker >= 0 {
				if marker > maximum {
					return nil, errRejected
				}
				line := append([]byte(nil), reader.buffer[:marker]...)
				reader.buffer = reader.buffer[marker+2:]
				total += len(line) + 2
				return line, nil
			}
			if len(reader.buffer) >= maximum {
				if err := reader.more(1); err != nil {
					return nil, err
				}
				if reader.buffer[maximum] != '\r' {
					return nil, errRejected
				}
				if err := reader.more(1); err != nil {
					return nil, err
				}
				if string(reader.buffer[maximum:maximum+2]) != "\r\n" {
					return nil, errRejected
				}
				line := append([]byte(nil), reader.buffer[:maximum]...)
				reader.buffer = reader.buffer[maximum+2:]
				total += len(line) + 2
				return line, nil
			}
			if err := reader.more(1); err != nil {
				return nil, err
			}
		}
	}
	statusLine, err := lineWithinTotal()
	if err != nil {
		return 0, nil, nil, err
	}
	parts := strings.SplitN(string(statusLine), " ", 3)
	if len(parts) < 2 || parts[0] != "HTTP/1.1" || len(parts[1]) != 3 {
		return 0, nil, nil, errRejected
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil || status < 100 || status > 999 {
		return 0, nil, nil, errRejected
	}
	headers := map[string]string{}
	for len(headers) < MaxHeaders {
		line, lineErr := lineWithinTotal()
		if lineErr != nil {
			return 0, nil, nil, lineErr
		}
		if len(line) == 0 {
			return status, headers, reader, nil
		}
		separator := bytes.IndexByte(line, ':')
		if separator < 0 {
			return 0, nil, nil, errRejected
		}
		name := strings.ToLower(string(line[:separator]))
		value := strings.TrimSpace(string(line[separator+1:]))
		if !isASCII(name) || !isASCII(value) || !headerName.MatchString(name) {
			return 0, nil, nil, errRejected
		}
		if _, exists := headers[name]; exists {
			return 0, nil, nil, errRejected
		}
		headers[name] = value
	}
	terminator, err := reader.exact(2)
	if err != nil || string(terminator) != "\r\n" {
		return 0, nil, nil, errRejected
	}
	return status, headers, reader, nil
}

func readBody(reader *wireReader, headers map[string]string) ([]byte, error) {
	if strings.ToLower(valueOr(headers, "content-encoding", "identity")) != "identity" {
		return nil, errRejected
	}
	transfer := strings.ToLower(headers["transfer-encoding"])
	contentLength, hasLength := headers["content-length"]
	if transfer != "" && hasLength {
		return nil, errRejected
	}
	var output bytes.Buffer
	if transfer == "chunked" {
		for {
			line, err := reader.line(128)
			if err != nil {
				return nil, err
			}
			token := line
			if index := bytes.IndexByte(token, ';'); index >= 0 {
				token = token[:index]
			}
			if !chunkBytes.Match(token) {
				return nil, errRejected
			}
			size64, parseErr := strconv.ParseUint(string(token), 16, 32)
			if parseErr != nil {
				return nil, errRejected
			}
			size := int(size64)
			if size == 0 {
				trailerBytes := 0
				for {
					trailer, trailerErr := reader.line(MaxHeaderLine)
					if trailerErr != nil {
						return nil, trailerErr
					}
					trailerBytes += len(trailer) + 2
					if trailerBytes > MaxHeaderBytes {
						return nil, errRejected
					}
					if len(trailer) == 0 {
						if output.Len() < 1 {
							return nil, errRejected
						}
						return output.Bytes(), nil
					}
					if !bytes.Contains(trailer, []byte{':'}) {
						return nil, errRejected
					}
				}
			}
			if size > MaxObjectBytes-output.Len() {
				return nil, errRejected
			}
			chunk, err := reader.exact(size)
			if err != nil {
				return nil, err
			}
			terminator, err := reader.exact(2)
			if err != nil || string(terminator) != "\r\n" {
				return nil, errRejected
			}
			_, _ = output.Write(chunk)
		}
	}
	if transfer != "" || !hasLength || !contentBytes.MatchString(contentLength) {
		return nil, errRejected
	}
	length, err := strconv.Atoi(contentLength)
	if err != nil || length < 1 || length > MaxObjectBytes {
		return nil, errRejected
	}
	for output.Len() < length {
		amount := min(65536, length-output.Len())
		chunk, readErr := reader.exact(amount)
		if readErr != nil {
			return nil, readErr
		}
		_, _ = output.Write(chunk)
	}
	return output.Bytes(), nil
}

func valueOr(values map[string]string, key, fallback string) string {
	if value, ok := values[key]; ok {
		return value
	}
	return fallback
}
func isASCII(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}
func digest(data []byte) string {
	value := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(value[:])
}

type reference struct {
	id           string
	project      map[string]any
	source       map[string]any
	declarations map[string]any
}
type sourceGroup struct {
	source     map[string]any
	metadata   string
	references []*reference
}

func sourceKind(value any) (string, error) {
	kind, ok := value.(string)
	if !ok {
		return "", errRejected
	}
	switch kind {
	case "changelog", "release_note", "migration_guide", "source_code", "helm_chart", "repository_metadata":
		return kind, nil
	}
	return "", errRejected
}

func closed(value any, fields ...string) (map[string]any, error) {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(fields) {
		return nil, errRejected
	}
	for _, field := range fields {
		if _, exists := object[field]; !exists {
			return nil, errRejected
		}
	}
	return object, nil
}

func parseRequest(value any) (string, []*reference, map[string]*sourceGroup, error) {
	document, err := closed(value, "schema", "revision", "authority", "requests")
	if err != nil || document["schema"] != Schema || document["authority"] != Authority {
		return "", nil, nil, errRejected
	}
	revision, err := sourcecorpus.ValidateSlug(document["revision"])
	if err != nil {
		return "", nil, nil, errRejected
	}
	requests, ok := document["requests"].([]any)
	if !ok || len(requests) < 1 || len(requests) > MaxLogicalRequests {
		return "", nil, nil, errRejected
	}
	seenIDs, seenLogical, projects := map[string]struct{}{}, map[string]struct{}{}, map[string]string{}
	logical := make([]*reference, 0, len(requests))
	sources := map[string]*sourceGroup{}
	for _, raw := range requests {
		record, recordErr := closed(raw, "id", "project", "source", "declarations")
		if recordErr != nil {
			return "", nil, nil, errRejected
		}
		id, idErr := sourcecorpus.ValidateSlug(record["id"])
		if idErr != nil {
			return "", nil, nil, errRejected
		}
		if _, exists := seenIDs[id]; exists {
			return "", nil, nil, errRejected
		}
		seenIDs[id] = struct{}{}
		project, projectErr := closed(record["project"], "slug", "canonicalRepositoryURL")
		if projectErr != nil {
			return "", nil, nil, errRejected
		}
		slug, slugErr := sourcecorpus.ValidateSlug(project["slug"])
		projectRepo, repoErr := sourcecorpus.ValidateRepository(project["canonicalRepositoryURL"])
		if slugErr != nil || repoErr != nil {
			return "", nil, nil, errRejected
		}
		if prior, exists := projects[slug]; exists && prior != projectRepo {
			return "", nil, nil, errRejected
		}
		projects[slug] = projectRepo
		source, sourceErr := closed(record["source"], "repositoryURL", "sourceKind", "version", "commit", "immutableURL", "fileDigest", "spans")
		if sourceErr != nil {
			return "", nil, nil, errRejected
		}
		repo, repoErr := sourcecorpus.ValidateRepository(source["repositoryURL"])
		kind, kindErr := sourceKind(source["sourceKind"])
		version, versionErr := sourcecorpus.ValidateVersion(source["version"])
		commit, commitErr := sourcecorpus.ValidateCommit(source["commit"])
		fileDigest, digestErr := sourcecorpus.ValidateSHA(source["fileDigest"])
		if repoErr != nil || kindErr != nil || versionErr != nil || commitErr != nil || digestErr != nil {
			return "", nil, nil, errRejected
		}
		immutable, immutableErr := sourcecorpus.ValidateImmutableURL(source["immutableURL"], repo, commit)
		spans, spansErr := sourcecorpus.ValidateSpansShape(source["spans"])
		if immutableErr != nil || spansErr != nil {
			return "", nil, nil, errRejected
		}
		canonicalSpans, _ := sourcecorpus.Canonical(spans)
		logicalKey := slug + "\x00" + immutable + "\x00" + digest(canonicalSpans)
		if _, exists := seenLogical[logicalKey]; exists {
			return "", nil, nil, errRejected
		}
		seenLogical[logicalKey] = struct{}{}
		declarations, declarationErr := sourcecorpus.ValidateDeclarations(record["declarations"])
		if declarationErr != nil {
			return "", nil, nil, errRejected
		}
		ownerRepo := strings.Split(strings.TrimPrefix(repo, "https://github.com/"), "/")
		path := strings.SplitN(immutable, "/blob/"+commit+"/", 2)[1]
		requestPath := "/" + ownerRepo[0] + "/" + ownerRepo[1] + "/" + commit + "/" + path
		if !rawPath.MatchString(requestPath) {
			return "", nil, nil, errRejected
		}
		rawURL := "https://" + RawHost + requestPath
		normalizedSource := map[string]any{"repositoryURL": repo, "sourceKind": kind, "version": version, "commit": commit, "immutableURL": immutable, "fileDigest": fileDigest, "spans": spans, "rawURL": rawURL, "requestPath": requestPath}
		metadata := strings.Join([]string{repo, kind, version, commit, fileDigest}, "\x00")
		group := sources[immutable]
		if group == nil {
			group = &sourceGroup{source: normalizedSource, metadata: metadata}
			sources[immutable] = group
		} else if group.metadata != metadata {
			return "", nil, nil, errRejected
		}
		item := &reference{id: id, project: map[string]any{"slug": slug, "canonicalRepositoryURL": projectRepo}, source: normalizedSource, declarations: declarations}
		group.references = append(group.references, item)
		logical = append(logical, item)
	}
	return revision, logical, sources, nil
}

func candidateManifest(logical []*reference, lengths map[string]int, revision, capturedAt string) map[string]any {
	sort.Slice(logical, func(i, j int) bool { return logical[i].id < logical[j].id })
	records := make([]any, 0, len(logical))
	for _, item := range logical {
		s := item.source
		fd := s["fileDigest"].(string)
		records = append(records, map[string]any{"id": item.id, "project": item.project, "source": map[string]any{"repositoryURL": s["repositoryURL"], "sourceKind": s["sourceKind"], "version": s["version"], "commit": s["commit"], "immutableURL": s["immutableURL"], "fileDigest": fd, "spans": s["spans"], "byteLength": int64(lengths[fd])}, "capture": map[string]any{"capturedAt": capturedAt, "object": "sha256/" + strings.TrimPrefix(fd, "sha256:")}, "declarations": item.declarations})
	}
	return map[string]any{"schema": sourcecorpus.Schema, "revision": revision, "authority": sourcecorpus.DeclaredAuthority, "records": records}
}

// Failure carries the canonical minimized attempt receipt.
type Failure struct{ Receipt []byte }

func (failure *Failure) Error() string { return "public source capture rejected" }

func attemptReceipt(requestDigest any, status string, captures []any, unattempted int64, cleanup string) []byte {
	receipt := map[string]any{"schema": ReceiptSchema, "requestDigest": requestDigest, "result": status, "authority": LocalAuthority, "captures": captures, "unattemptedSourceCount": unattempted, "cleanup": cleanup, "limitations": []any{"attempt metadata is not source, tag, rule, runtime, signing, publication, or training authority", "response bodies, local paths, redirect targets, exception text, and invalid caller values are omitted"}}
	canonical, err := sourcecorpus.Canonical(receipt)
	if err == nil && len(canonical) <= MaxReceiptBytes {
		return canonical
	}
	fallback := map[string]any{"schema": ReceiptSchema, "requestDigest": nil, "result": "REJECTED", "authority": LocalAuthority, "captures": []any{}, "unattemptedSourceCount": int64(0), "cleanup": "NOT_APPLICABLE", "limitations": []any{"attempt receipt exceeded its local bound"}}
	canonical, _ = sourcecorpus.Canonical(fallback)
	return canonical
}

// Capture validates one closed request, fetches each unique immutable source
// once, and writes an exclusive candidate tree. Success bytes include
// outputName; the retained completion receipt intentionally does not.
func Capture(ctx context.Context, raw []byte, outputParent string, fetcher Fetcher, now func() time.Time) ([]byte, error) {
	value, err := sourcecorpus.DecodeBounded(raw, MaxRequestBytes)
	if err != nil {
		return nil, errRejected
	}
	canonicalRequest, err := sourcecorpus.Canonical(value)
	if err != nil || len(canonicalRequest) > MaxRequestBytes {
		return nil, errRejected
	}
	requestDigest := digest(canonicalRequest)
	revision, logical, sources, err := parseRequest(value)
	if err != nil {
		return nil, errRejected
	}
	prospective, _ := sourcecorpus.Canonical(candidateManifest(logical, mapAllLengths(logical, MaxObjectBytes), revision, "2000-01-01T00:00:00Z"))
	if len(prospective)+1 > 256*1024 {
		return nil, errRejected
	}
	if sourcecorpus.ValidatePrivateDirectoryPath(outputParent) != nil {
		return nil, errRejected
	}
	destination := "capture-" + strings.TrimPrefix(requestDigest, "sha256:")
	if sourcecorpus.EnsurePrivateChildAbsent(outputParent, destination) != nil {
		return nil, errRejected
	}
	if fetcher == nil {
		fetcher = FixedHTTPSFetcher{}
	}
	if now == nil {
		now = time.Now
	}
	attemptCtx, cancel := context.WithTimeout(ctx, AttemptTimeout)
	defer cancel()
	keys := make([]string, 0, len(sources))
	for key := range sources {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	objects := map[string][]byte{}
	captures := make([]any, 0, len(keys))
	capturedAt := now().UTC().Truncate(time.Second).Format("2006-01-02T15:04:05Z")
	fail := func() ([]byte, error) {
		receipt := attemptReceipt(requestDigest, "REJECTED", captures, int64(len(keys)-len(captures)), "NOT_APPLICABLE")
		return nil, &Failure{Receipt: receipt}
	}
	for _, immutable := range keys {
		group := sources[immutable]
		source := group.source
		references := make([]any, 0, len(group.references))
		sort.Slice(group.references, func(i, j int) bool { return group.references[i].id < group.references[j].id })
		for _, item := range group.references {
			references = append(references, map[string]any{"id": item.id, "project": item.project})
		}
		public := map[string]any{"immutableURL": immutable, "requestedURL": source["rawURL"], "observedURL": source["rawURL"], "references": references}
		if attemptCtx.Err() != nil {
			public["status"] = "ATTEMPT_TIMEOUT"
			captures = append(captures, public)
			return fail()
		}
		sourceCtx, sourceCancel := context.WithTimeout(attemptCtx, PerSourceTimeout)
		result := fetcher.Fetch(sourceCtx, source["requestPath"].(string))
		timedOut := sourceCtx.Err() != nil
		sourceCancel()
		if timedOut {
			result = FetchResult{Kind: "TRANSPORT_TIMEOUT"}
		}
		if result.Kind != "HTTP_200" || result.StatusCode != 200 || len(result.Body) < 1 || len(result.Body) > MaxObjectBytes {
			allowed := map[string]bool{"HTTP_STATUS": true, "TRANSPORT_TIMEOUT": true, "TRANSPORT_FAILURE": true, "RESPONSE_REJECTED": true}
			status := result.Kind
			if !allowed[status] {
				status = "TRANSPORT_FAILURE"
			}
			public["status"] = status
			if status == "HTTP_STATUS" && result.StatusCode >= 100 && result.StatusCode <= 599 {
				public["httpStatus"] = int64(result.StatusCode)
			}
			captures = append(captures, public)
			return fail()
		}
		observed := digest(result.Body)
		if observed != source["fileDigest"] {
			public["status"] = "DIGEST_MISMATCH"
			public["httpStatus"] = int64(200)
			public["observedDigest"] = observed
			public["byteLength"] = int64(len(result.Body))
			captures = append(captures, public)
			return fail()
		}
		for _, item := range group.references {
			if _, _, spanErr := sourcecorpus.VerifySpans(item.source["spans"], result.Body); spanErr != nil {
				public["status"] = "SPAN_MISMATCH"
				public["httpStatus"] = int64(200)
				public["observedDigest"] = observed
				public["byteLength"] = int64(len(result.Body))
				captures = append(captures, public)
				return fail()
			}
		}
		if _, exists := objects[observed]; !exists {
			objects[observed] = append([]byte(nil), result.Body...)
		}
		aggregate := 0
		for _, data := range objects {
			aggregate += len(data)
		}
		if aggregate > MaxUniqueBytes {
			public["status"] = "AGGREGATE_LIMIT"
			public["httpStatus"] = int64(200)
			public["observedDigest"] = observed
			public["byteLength"] = int64(len(result.Body))
			captures = append(captures, public)
			return fail()
		}
		public["status"] = "MATCHED_DECLARED_BYTES"
		public["httpStatus"] = int64(200)
		public["observedDigest"] = observed
		public["byteLength"] = int64(len(result.Body))
		public["object"] = "sha256/" + strings.TrimPrefix(observed, "sha256:")
		captures = append(captures, public)
	}
	lengths := map[string]int{}
	aggregate := 0
	for key, data := range objects {
		lengths[key] = len(data)
		aggregate += len(data)
	}
	manifest := candidateManifest(logical, lengths, revision, capturedAt)
	manifestBytes, _ := sourcecorpus.Canonical(manifest)
	receipt := map[string]any{"schema": ReceiptSchema, "requestDigest": requestDigest, "result": "MATCHED_DECLARED_BYTES", "authority": LocalAuthority, "revision": revision, "logicalRequestCount": int64(len(logical)), "uniqueSourceCount": int64(len(sources)), "aggregateByteLength": int64(aggregate), "captures": captures, "candidateManifestDigest": digest(manifestBytes), "cleanup": "NOT_APPLICABLE", "limitations": []any{"capture verifies only declared byte and span consistency; it does not authenticate source ownership, tags, releases, licences, rules, runtime behavior, signing, publication, or training", "project, packet, rule, version, and capture-time fields remain declarations; the candidate manifest needs separate offline verification and independent source review"}}
	receiptBytes, err := sourcecorpus.Canonical(receipt)
	if err != nil || len(receiptBytes) > MaxReceiptBytes {
		return nil, errRejected
	}
	if err = sourcecorpus.WriteCaptureTree(outputParent, destination, objects, manifestBytes, receiptBytes); err != nil {
		cleanup := "INCOMPLETE"
		var writeFailure *sourcecorpus.WriteFailure
		if errors.As(err, &writeFailure) {
			cleanup = writeFailure.Cleanup
		}
		return nil, &Failure{Receipt: attemptReceipt(requestDigest, "REJECTED", captures, 0, cleanup)}
	}
	receipt["outputName"] = destination
	return sourcecorpus.Canonical(receipt)
}

func mapAllLengths(logical []*reference, length int) map[string]int {
	result := map[string]int{}
	for _, item := range logical {
		result[item.source["fileDigest"].(string)] = length
	}
	return result
}

// Run is the redacted command adapter for the future maintainer CLI.
func Run(ctx context.Context, args []string, stdout, stderr io.Writer, fetcher Fetcher, now func() time.Time) int {
	if len(args) != 5 || args[0] != "capture" || args[1] != "--request" || args[3] != "--output-parent" {
		_, _ = stdout.Write(append(attemptReceipt(nil, "REJECTED", []any{}, 0, "NOT_APPLICABLE"), '\n'))
		_, _ = io.WriteString(stderr, "public-source-capture: capture rejected\n")
		return 2
	}
	raw, err := sourcecorpus.ReadPrivateFile(args[2], MaxRequestBytes)
	if err == nil {
		var output []byte
		output, err = Capture(ctx, raw, args[4], fetcher, now)
		if err == nil {
			if written, writeErr := stdout.Write(append(output, '\n')); writeErr == nil && written == len(output)+1 {
				return 0
			}
			_, _ = io.WriteString(stderr, "public-source-capture: capture rejected\n")
			return 2
		}
	}
	var failure *Failure
	if errors.As(err, &failure) {
		_, _ = stdout.Write(append(failure.Receipt, '\n'))
	} else {
		_, _ = stdout.Write(append(attemptReceipt(nil, "REJECTED", []any{}, 0, "NOT_APPLICABLE"), '\n'))
	}
	_, _ = io.WriteString(stderr, "public-source-capture: capture rejected\n")
	return 2
}
