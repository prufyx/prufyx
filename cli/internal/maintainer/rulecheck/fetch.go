// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

// maxFetchBytes bounds a downloaded blob. Source files cited by a rule are
// small text/code files; anything larger indicates the wrong target.
const maxFetchBytes = 8 << 20

// HTTPFetcher is the production Fetcher: a plain net/http GET restricted to
// raw.githubusercontent.com by construction (Validate only ever builds URLs
// on that host from an already-validated github.com blob URL).
type HTTPFetcher struct {
	Client *http.Client
}

func (f HTTPFetcher) FetchRawBlob(ctx context.Context, rawURL string) ([]byte, error) {
	client := f.Client
	if client == nil {
		client = http.DefaultClient
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %s fetching %s", response.Status, rawURL)
	}
	limited := io.LimitReader(response.Body, maxFetchBytes+1)
	content, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(content) > maxFetchBytes {
		return nil, fmt.Errorf("%s exceeds the %d byte fetch limit", rawURL, maxFetchBytes)
	}
	return content, nil
}
