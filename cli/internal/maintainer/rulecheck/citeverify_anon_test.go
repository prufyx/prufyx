// SPDX-License-Identifier: AGPL-3.0-only

package rulecheck

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestGitHubObjectsAnonymousRetryAfter403(t *testing.T) {
	tests := []struct {
		name       string
		token      string
		first      func(http.Header) // headers of the authenticated 403
		anonStatus int               // answer to the token-less request
		wantStatus int
		wantCalls  int // requests that reached the server
		wantAnon   int // of those, without Authorization
		wantAdmit  int
		wantObs    int
		wantObsAny int
	}{
		{name: "allow list 403 then anonymous 200", token: "t", anonStatus: 200, wantStatus: 200, wantCalls: 2, wantAnon: 1, wantAdmit: 2, wantObs: 1, wantObsAny: 1},
		{name: "anonymous also refused: one retry only", token: "t", anonStatus: 403, wantStatus: 403, wantCalls: 2, wantAnon: 1, wantAdmit: 2, wantObs: 1, wantObsAny: 1},
		{name: "primary rate limit 403 is not retried", token: "t", first: func(h http.Header) { h.Set("X-RateLimit-Remaining", "0") }, anonStatus: 200, wantStatus: 403, wantCalls: 1, wantAdmit: 1, wantObs: 1},
		{name: "secondary rate limit 403 is not retried", token: "t", first: func(h http.Header) { h.Set("Retry-After", "30") }, anonStatus: 200, wantStatus: 403, wantCalls: 1, wantAdmit: 1, wantObs: 1},
		{name: "no token: nothing to drop", token: "", anonStatus: 200, wantStatus: 403, wantCalls: 1, wantAnon: 1, wantAdmit: 1, wantObs: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			calls, anon := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				calls++
				if r.Header.Get("Authorization") == "" {
					anon++
					if tc.token != "" {
						w.WriteHeader(tc.anonStatus)
						return
					}
				}
				if tc.first != nil {
					tc.first(w.Header())
				}
				w.WriteHeader(http.StatusForbidden)
			}))
			defer server.Close()
			var admit, obs, obsAnon int
			g := GitHubObjects{APIBase: server.URL, Token: tc.token, Client: server.Client()}
			g.Admit = func() error { admit++; return nil }
			g.Observe = func(*http.Response) error { obs++; return nil }
			g.ObserveAnon = func(*http.Response) error { obsAnon++; return nil }
			_, status, err := g.get(context.Background(), server.URL+"/x")
			if err != nil {
				t.Fatal(err)
			}
			if status != tc.wantStatus || calls != tc.wantCalls || anon != tc.wantAnon || admit != tc.wantAdmit {
				t.Fatalf("status %d calls %d anon %d admit %d, want %d/%d/%d/%d", status, calls, anon, admit, tc.wantStatus, tc.wantCalls, tc.wantAnon, tc.wantAdmit)
			}
			// The authenticated response goes to Observe, the retry to
			// ObserveAnon only: the anonymous pool never reaches the
			// token's budget reading.
			if obs != tc.wantObs || obsAnon != tc.wantObsAny {
				t.Fatalf("observe %d observeAnon %d, want %d/%d", obs, obsAnon, tc.wantObs, tc.wantObsAny)
			}
		})
	}
}

func TestGitHubObjectsAnonymousRetryRefusedByBudget(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()
	n := 0
	g := GitHubObjects{APIBase: server.URL, Token: "t", Client: server.Client()}
	g.Admit = func() error {
		n++
		if n > 1 {
			return http.ErrAbortHandler
		}
		return nil
	}
	_, _, err := g.get(context.Background(), server.URL+"/x")
	if err == nil || calls != 1 {
		t.Fatalf("budget refusal of the retry: err %v calls %d, want an error after 1 request", err, calls)
	}
}
