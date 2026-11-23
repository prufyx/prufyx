// SPDX-License-Identifier: AGPL-3.0-only

package evidencerepin

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestApiGetForbiddenTyped(t *testing.T) {
	f := &fakeAPIFetcher{responses: map[string]forbiddenResp{"/p": {[]byte(`{"message":"Forbidden"}`), 403}}}
	if _, err := apiGet(context.Background(), f, "/p"); !errors.Is(err, errRepoForbidden) || errors.Is(err, errRateLimited) {
		t.Fatalf("got %v", err)
	}
}

func TestForbiddenIsNotQuotaHeaders(t *testing.T) {
	ok := []byte(`{"message":"Forbidden"}`)
	h := func(kv ...string) http.Header {
		hd := http.Header{}
		for i := 0; i < len(kv); i += 2 {
			hd.Set(kv[i], kv[i+1])
		}
		return hd
	}
	cases := []struct {
		name string
		hd   http.Header
		body []byte
		want bool
	}{
		{"proven", h("X-RateLimit-Remaining", "4949"), ok, true},
		{"remaining zero", h("X-RateLimit-Remaining", "0"), ok, false},
		{"remaining missing", h(), ok, false},
		{"remaining garbage", h("X-RateLimit-Remaining", "x"), ok, false},
		{"remaining negative", h("X-RateLimit-Remaining", "-1"), ok, false},
		{"retry-after", h("X-RateLimit-Remaining", "10", "Retry-After", "60"), ok, false},
		{"secondary body", h("X-RateLimit-Remaining", "10"), []byte(`{"message":"secondary rate limit"}`), false},
	}
	for _, c := range cases {
		if got := forbiddenIsNotQuota(c.hd, c.body); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestFetchClassifiesForbidden(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header http.Header
		body   string
		want   int
	}{
		{"proven non-quota", http.Header{"X-Ratelimit-Remaining": {"4949"}}, `{"message":"Forbidden"}`, 403},
		{"remaining zero", http.Header{"X-Ratelimit-Remaining": {"0"}}, `{"message":"Forbidden"}`, 429},
		{"no headers", nil, `{"message":"Forbidden"}`, 429},
		{"retry-after", http.Header{"X-Ratelimit-Remaining": {"9"}, "Retry-After": {"60"}}, `{"message":"Forbidden"}`, 429},
		{"secondary message", http.Header{"X-Ratelimit-Remaining": {"9"}}, `{"message":"You have exceeded a secondary rate limit"}`, 429},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.header {
					w.Header()[k] = v
				}
				w.WriteHeader(403)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			_, status, err := GitHubAPIFetcher{}.fetchClassified(context.Background(), "/x", diagnosticClient(t, server))
			if err != nil || status != tc.want {
				t.Fatalf("status %d err %v, want %d", status, err, tc.want)
			}
		})
	}
}
