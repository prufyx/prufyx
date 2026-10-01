// SPDX-License-Identifier: AGPL-3.0-only

package sourcecapture

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/prufyx/prufyx/cli/internal/maintainer/sourcecorpus"
)

type brokenWriter struct {
	err   error
	short bool
}

type passthroughHandshakeConn struct {
	net.Conn
	handshake chan<- struct{}
}

func (connection passthroughHandshakeConn) HandshakeContext(context.Context) error {
	connection.handshake <- struct{}{}
	return nil
}

func (w brokenWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.short && len(p) > 0 {
		return len(p) - 1, nil
	}
	return len(p), nil
}

func captureFixture(parts ...string) string {
	items := append([]string{"..", "..", "..", "examples"}, parts...)
	return filepath.Join(items...)
}

func receiptObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value map[string]any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func fixtureRequest(t *testing.T) ([]byte, []byte) {
	t.Helper()
	raw, err := os.ReadFile(captureFixture("capture", "synthetic-capture-request.json"))
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(captureFixture("corpus", "objects", "sha256", "2aa55d81765ce03e46eaeaa27a4314ed8663bd7ec8fc27e46ab0a5f7dc6e6366"))
	if err != nil {
		t.Fatal(err)
	}
	return raw, body
}

func privateParent(t *testing.T) string {
	t.Helper()
	parent := filepath.Join(t.TempDir(), "capture-parent")
	if err := os.Mkdir(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	return parent
}

func TestCaptureWritesVerifiableCandidateWithOneMinimizedFetch(t *testing.T) {
	raw, body := fixtureRequest(t)
	value, err := sourcecorpus.DecodeBounded(raw, MaxRequestBytes)
	if err != nil {
		t.Fatal(err)
	}
	document := value.(map[string]any)
	first := document["requests"].([]any)[0]
	copyRaw, _ := sourcecorpus.Canonical(first)
	secondValue, _ := sourcecorpus.DecodeBounded(copyRaw, MaxRequestBytes)
	second := secondValue.(map[string]any)
	second["id"] = "other-reference"
	second["project"] = map[string]any{"slug": "other-project", "canonicalRepositoryURL": "https://github.com/example/other-project"}
	document["requests"] = append(document["requests"].([]any), second)
	raw, _ = sourcecorpus.Canonical(document)
	called := 0
	fetcher := FetchFunc(func(_ context.Context, path string) FetchResult {
		called++
		expected := "/example/synthetic-source/0123456789abcdef0123456789abcdef01234567/CHANGELOG.md"
		if path != expected {
			t.Fatalf("unexpected egress path %q", path)
		}
		return FetchResult{Kind: "HTTP_200", StatusCode: 200, Body: body}
	})
	parent := privateParent(t)
	result, err := Capture(context.Background(), raw, parent, fetcher, func() time.Time { return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC) })
	if err != nil {
		var failure *Failure
		if errors.As(err, &failure) {
			t.Fatalf("capture failed (%T): %v %s", err, err, failure.Receipt)
		}
		t.Fatalf("capture failed (%T): %v", err, err)
	}
	if called != 1 {
		t.Fatalf("shared immutable URL fetched %d times", called)
	}
	receipt := receiptObject(t, result)
	if receipt["result"] != "MATCHED_DECLARED_BYTES" || receipt["logicalRequestCount"] != json.Number("2") || receipt["uniqueSourceCount"] != json.Number("1") || receipt["aggregateByteLength"] != json.Number("52") {
		t.Fatalf("unexpected receipt: %#v", receipt)
	}
	outputName := receipt["outputName"].(string)
	output := filepath.Join(parent, outputName)
	manifestPath := filepath.Join(output, "CANDIDATE-CORPUS-MANIFEST.json")
	manifest, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = sourcecorpus.Verify(manifest, filepath.Join(output, "objects")); err != nil {
		t.Fatalf("candidate did not pass offline verifier: %v", err)
	}
	storedReceipt, err := os.ReadFile(filepath.Join(output, "CAPTURE-RECEIPT.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(storedReceipt, []byte("outputName")) {
		t.Fatal("retained receipt contains local output name")
	}
	for _, path := range []string{output, filepath.Join(output, "objects"), filepath.Join(output, "objects", "sha256")} {
		info, statErr := os.Stat(path)
		if statErr != nil || info.Mode().Perm() != 0o700 {
			t.Fatalf("directory mode %s: %v %#o", path, statErr, info.Mode().Perm())
		}
	}
	for _, path := range []string{manifestPath, filepath.Join(output, "CAPTURE-RECEIPT.json"), filepath.Join(output, "objects", "sha256", strings.TrimPrefix(digest(body), "sha256:"))} {
		info, statErr := os.Stat(path)
		if statErr != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("file mode %s: %v %#o", path, statErr, info.Mode().Perm())
		}
	}
}

func TestCaptureRejectsInvalidInputBeforeFetcher(t *testing.T) {
	raw, _ := fixtureRequest(t)
	parent := privateParent(t)
	calls := 0
	fetcher := FetchFunc(func(context.Context, string) FetchResult { calls++; return FetchResult{Kind: "TRANSPORT_FAILURE"} })
	cases := [][]byte{
		[]byte(`{"schema":"x","schema":"y"}`),
		bytes.Replace(raw, []byte("https://github.com/example/synthetic-source/blob/"), []byte("http://attacker.invalid/blob/"), 1),
	}
	for _, candidate := range cases {
		if _, err := Capture(context.Background(), candidate, parent, fetcher, time.Now); !errors.Is(err, Error) {
			t.Fatalf("invalid request accepted: %v", err)
		}
	}
	if calls != 0 {
		t.Fatalf("fetcher called %d times for invalid requests", calls)
	}
}

func TestCaptureDoesNotFetchWhenDestinationExists(t *testing.T) {
	raw, _ := fixtureRequest(t)
	value, _ := sourcecorpus.DecodeBounded(raw, MaxRequestBytes)
	canonical, _ := sourcecorpus.Canonical(value)
	destination := "capture-" + strings.TrimPrefix(digest(canonical), "sha256:")
	parent := privateParent(t)
	if err := os.Mkdir(filepath.Join(parent, destination), 0o700); err != nil {
		t.Fatal(err)
	}
	calls := 0
	fetcher := FetchFunc(func(context.Context, string) FetchResult { calls++; return FetchResult{Kind: "TRANSPORT_FAILURE"} })
	if _, err := Capture(context.Background(), raw, parent, fetcher, time.Now); !errors.Is(err, Error) {
		t.Fatalf("existing destination accepted: %v", err)
	}
	if calls != 0 {
		t.Fatalf("fetcher called %d times before existing-output rejection", calls)
	}
}

func TestCaptureRejectsPermissiveOrLinkedParentBeforeFetcher(t *testing.T) {
	raw, _ := fixtureRequest(t)
	calls := 0
	fetcher := FetchFunc(func(context.Context, string) FetchResult {
		calls++
		return FetchResult{Kind: "TRANSPORT_FAILURE"}
	})
	parent := privateParent(t)
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Capture(context.Background(), raw, parent, fetcher, time.Now); !errors.Is(err, Error) {
		t.Fatalf("permissive parent accepted: %v", err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(t.TempDir(), "parent-link")
	if err := os.Symlink(parent, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := Capture(context.Background(), raw, alias, fetcher, time.Now); !errors.Is(err, Error) {
		t.Fatalf("linked parent accepted: %v", err)
	}
	if calls != 0 {
		t.Fatalf("fetcher called %d times before parent admission", calls)
	}
}

func TestCaptureFailureReceiptsMinimizeRedirectDigestAndTimeout(t *testing.T) {
	raw, body := fixtureRequest(t)
	cases := []struct {
		name   string
		fetch  FetchFunc
		status string
	}{
		{"redirect", func(context.Context, string) FetchResult { return FetchResult{Kind: "HTTP_STATUS", StatusCode: 302} }, "HTTP_STATUS"},
		{"digest", func(context.Context, string) FetchResult {
			return FetchResult{Kind: "HTTP_200", StatusCode: 200, Body: append([]byte(nil), body[:len(body)-1]...)}
		}, "DIGEST_MISMATCH"},
		{"timeout", func(ctx context.Context, _ string) FetchResult {
			<-ctx.Done()
			return FetchResult{Kind: "HTTP_200", StatusCode: 200, Body: body}
		}, "TRANSPORT_TIMEOUT"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ctx := context.Background()
			if test.name == "timeout" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 5*time.Millisecond)
				defer cancel()
			}
			parent := privateParent(t)
			_, err := Capture(ctx, raw, parent, test.fetch, time.Now)
			var failure *Failure
			if !errors.As(err, &failure) {
				t.Fatalf("expected minimized failure, got %v", err)
			}
			receipt := receiptObject(t, failure.Receipt)
			captures := receipt["captures"].([]any)
			if len(captures) != 1 || captures[0].(map[string]any)["status"] != test.status {
				t.Fatalf("unexpected failure receipt: %#v", receipt)
			}
			text := string(failure.Receipt)
			for _, secret := range []string{"Location", "response body", parent} {
				if strings.Contains(text, secret) {
					t.Fatalf("receipt leaked %q: %s", secret, text)
				}
			}
			entries, readErr := os.ReadDir(parent)
			if readErr != nil || len(entries) != 0 {
				t.Fatalf("failed capture left output: %v %#v", readErr, entries)
			}
		})
	}
}

func TestFixedHTTPSFetcherCancellationClosesEstablishedConnection(t *testing.T) {
	for _, variable := range []string{"SSL_CERT_FILE", "SSL_CERT_DIR", "SSLKEYLOGFILE"} {
		t.Setenv(variable, "")
	}
	client, server := net.Pipe()
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	handshake := make(chan struct{}, 1)
	requestRead := make(chan struct{}, 1)
	serverClosed := make(chan error, 1)
	go func() {
		request := make([]byte, 0, 512)
		one := make([]byte, 1)
		for !bytes.HasSuffix(request, []byte("\r\n\r\n")) {
			count, err := server.Read(one)
			if err != nil {
				serverClosed <- err
				return
			}
			request = append(request, one[:count]...)
		}
		requestRead <- struct{}{}
		_, err := server.Read(one)
		serverClosed <- err
	}()

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan FetchResult, 1)
	go func() {
		result <- fetchFixedHTTPS(
			ctx,
			"/example/synthetic-source/0123456789abcdef0123456789abcdef01234567/CHANGELOG.md",
			func(_ context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != net.JoinHostPort(RawHost, RawPort) {
					t.Errorf("unexpected dial target %q %q", network, address)
				}
				return client, nil
			},
			func(raw net.Conn) handshakingConn {
				return passthroughHandshakeConn{Conn: raw, handshake: handshake}
			},
		)
	}()
	select {
	case <-handshake:
	case <-time.After(time.Second):
		t.Fatal("transport did not complete injected handshake")
	}
	select {
	case <-requestRead:
	case <-time.After(time.Second):
		t.Fatal("transport did not issue request")
	}
	cancel()
	select {
	case outcome := <-result:
		if outcome.Kind != "TRANSPORT_FAILURE" {
			t.Fatalf("cancelled transport returned %#v", outcome)
		}
	case <-time.After(time.Second):
		t.Fatal("cancelled transport remained blocked after handshake")
	}
	select {
	case err := <-serverClosed:
		if err == nil {
			t.Fatal("peer did not observe connection closure")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not close established connection")
	}
}

func TestHTTPParserEnforcesRedirectHeaderAndBodyBounds(t *testing.T) {
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 3\r\nContent-Encoding: identity\r\n\r\nabcEXTRA")
	status, headers, reader, err := readHeader(bytes.NewReader(response))
	if err != nil || status != 200 {
		t.Fatalf("header: %d %v", status, err)
	}
	body, err := readBody(reader, headers)
	if err != nil || string(body) != "abc" {
		t.Fatalf("body: %q %v", body, err)
	}
	duplicate := []byte("HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx")
	if _, _, _, err := readHeader(bytes.NewReader(duplicate)); err == nil {
		t.Fatal("duplicate response header accepted")
	}
	oversized := []byte("HTTP/1.1 200 OK\r\nContent-Length: 4194305\r\n\r\n")
	_, headers, reader, err = readHeader(bytes.NewReader(oversized))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = readBody(reader, headers); err == nil {
		t.Fatal("oversized response accepted")
	}
	chunked := []byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n")
	_, headers, reader, err = readHeader(bytes.NewReader(chunked))
	if err != nil {
		t.Fatal(err)
	}
	body, err = readBody(reader, headers)
	if err != nil || string(body) != "abc" {
		t.Fatalf("chunked body: %q %v", body, err)
	}
	redirect := []byte("HTTP/1.1 302 Found\r\nLocation: https://attacker.invalid/private\r\nContent-Length: 0\r\n\r\n")
	status, _, _, err = readHeader(bytes.NewReader(redirect))
	if err != nil || status != 302 {
		t.Fatalf("redirect status was not retained without following: %d %v", status, err)
	}
	var fields strings.Builder
	for index := 0; index < MaxHeaders; index++ {
		_, _ = fmt.Fprintf(&fields, "x-%d: v\r\n", index)
	}
	exactHeaders := []byte("HTTP/1.1 200 OK\r\n" + fields.String() + "\r\n")
	if _, values, _, err := readHeader(bytes.NewReader(exactHeaders)); err != nil || len(values) != MaxHeaders {
		t.Fatalf("exact header bound rejected: %d %v", len(values), err)
	}
	tooMany := []byte("HTTP/1.1 200 OK\r\n" + fields.String() + "x-extra: v\r\n\r\n")
	if _, _, _, err := readHeader(bytes.NewReader(tooMany)); err == nil {
		t.Fatal("65th response header accepted")
	}
}

func TestRunRedactsInvalidCallerPath(t *testing.T) {
	var stdout, stderr bytes.Buffer
	status := Run(context.Background(), []string{"capture", "--request", "/private/SECRET-CANARY", "--output-parent", "/private/output"}, &stdout, &stderr, nil, time.Now)
	if status != 2 || strings.Contains(stdout.String()+stderr.String(), "SECRET-CANARY") || !strings.Contains(stderr.String(), "capture rejected") {
		t.Fatalf("unredacted run failure: %d %q %q", status, stdout.String(), stderr.String())
	}
}

func TestRunRejectsReceiptWriteFailure(t *testing.T) {
	raw, body := fixtureRequest(t)
	request := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(request, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	fetcher := FetchFunc(func(context.Context, string) FetchResult {
		return FetchResult{Kind: "HTTP_200", StatusCode: 200, Body: body}
	})
	for _, output := range []brokenWriter{{err: io.ErrClosedPipe}, {short: true}} {
		parent := privateParent(t)
		var stderr bytes.Buffer
		status := Run(context.Background(), []string{"capture", "--request", request, "--output-parent", parent}, output, &stderr, fetcher, func() time.Time {
			return time.Date(2026, 9, 11, 12, 0, 0, 0, time.UTC)
		})
		if status == 0 || stderr.String() != "public-source-capture: capture rejected\n" {
			t.Fatalf("write failure returned status=%d stderr=%q", status, stderr.String())
		}
	}
}
