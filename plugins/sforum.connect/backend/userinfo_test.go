package main

import (
	"context"
	"net/http"
	"testing"
)

func TestAssertionFromProfile(t *testing.T) {
	cases := []struct {
		name    string
		profile remoteProfile
		want    IdentityAssertion
	}{
		{
			name: "sub wins over id",
			profile: remoteProfile{
				Sub: "sub-1", ID: float64(7), Username: "alice", DisplayName: "Alice",
				Email: "Alice@Example.com", EmailVerified: true,
			},
			want: IdentityAssertion{
				ProviderSubject: "sub-1", UsernameHint: "alice", DisplayName: "Alice",
				EmailHint: "alice@example.com", EmailVerified: true,
			},
		},
		{
			name: "numeric id fallback",
			profile: remoteProfile{
				ID: float64(42), Username: "bob",
			},
			want: IdentityAssertion{
				ProviderSubject: "42", UsernameHint: "bob", DisplayName: "bob",
			},
		},
		{
			name: "string id fallback",
			profile: remoteProfile{
				ID: "123", Username: "carol", DisplayName: "Carol",
			},
			want: IdentityAssertion{
				ProviderSubject: "123", UsernameHint: "carol", DisplayName: "Carol",
			},
		},
		{
			name: "unverified email is dropped",
			profile: remoteProfile{
				Sub: "s", Username: "dave", Email: "dave@example.com", EmailVerified: false,
			},
			want: IdentityAssertion{
				ProviderSubject: "s", UsernameHint: "dave", DisplayName: "dave",
			},
		},
		{
			name: "email without verification flag is dropped",
			profile: remoteProfile{
				Sub: "s", Username: "erin", Email: "erin@example.com",
			},
			want: IdentityAssertion{
				ProviderSubject: "s", UsernameHint: "erin", DisplayName: "erin",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := assertionFromProfile(tc.profile)
			if err != nil {
				t.Fatalf("assertion: %v", err)
			}
			if got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestAssertionFromProfileRejectsMissingSubject(t *testing.T) {
	_, err := assertionFromProfile(remoteProfile{Username: "nobody"})
	if reason := publicReason(err); reason != reasonSubjectMissing {
		t.Fatalf("reason = %q", reason)
	}
	_, err = assertionFromProfile(remoteProfile{ID: 1.5})
	if reason := publicReason(err); reason != reasonSubjectMissing {
		t.Fatalf("fractional id reason = %q", reason)
	}
	_, err = assertionFromProfile(remoteProfile{ID: "12a"})
	if reason := publicReason(err); reason != reasonSubjectMissing {
		t.Fatalf("non-numeric id reason = %q", reason)
	}
}

func TestAssertionFromProfileTruncates(t *testing.T) {
	long := make([]byte, 400)
	for i := range long {
		long[i] = 'a'
	}
	profile := remoteProfile{
		Sub: string(long), Username: string(long), DisplayName: string(long),
		Email: string(long) + "@example.com", EmailVerified: true,
	}
	got, err := assertionFromProfile(profile)
	if err != nil {
		t.Fatalf("assertion: %v", err)
	}
	if len(got.ProviderSubject) != 320 {
		t.Fatalf("subject length = %d", len(got.ProviderSubject))
	}
	if len(got.UsernameHint) != 64 {
		t.Fatalf("username length = %d", len(got.UsernameHint))
	}
	if len(got.DisplayName) != 200 {
		t.Fatalf("display length = %d", len(got.DisplayName))
	}
	if len(got.EmailHint) != 320 {
		t.Fatalf("email length = %d", len(got.EmailHint))
	}
}

func TestCompleteIdentity(t *testing.T) {
	fake := newFakeProvider(t)
	oauth := NewSForumOAuth(fake.config(), nil)
	verifier := "verifier-abcdefghijklmnopqrstuvwxyz-0123456789"
	code := fake.IssueCode(s256(verifier))

	assertion, err := oauth.CompleteIdentity(context.Background(), code, verifier, fake.RedirectURI)
	if err != nil {
		t.Fatalf("complete: %v", err)
	}
	if assertion.ProviderSubject != "42" {
		t.Fatalf("subject = %q", assertion.ProviderSubject)
	}
	if assertion.UsernameHint != "alice" || assertion.DisplayName != "Alice" {
		t.Fatalf("hints = %q / %q", assertion.UsernameHint, assertion.DisplayName)
	}
	if assertion.EmailHint != "alice@example.com" || !assertion.EmailVerified {
		t.Fatalf("email = %q verified=%v", assertion.EmailHint, assertion.EmailVerified)
	}
	// userinfo 必须走查询参数，Bearer 头到不了 SForum 的插件路由。
	if got := fake.LastUserinfoQuery().Get("access_token"); got != fake.AccessToken {
		t.Fatalf("access_token query = %q", got)
	}
}

func TestFetchProfileErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		reason string
	}{
		{"unauthorized", http.StatusUnauthorized, `{"error":"invalid_token"}`, reasonUserUnauthorized},
		{"bad request", http.StatusBadRequest, `{"error":"invalid_request"}`, reasonUserRequestInvalid},
		{"server error", http.StatusInternalServerError, `{}`, reasonUserServerError},
		{"malformed", http.StatusOK, "not json", reasonUserMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeProvider(t)
			fake.UserinfoStatus = tc.status
			fake.UserinfoBody = tc.body
			oauth := NewSForumOAuth(fake.config(), nil)

			_, err := oauth.fetchProfile(context.Background(), fake.AccessToken)
			if err == nil {
				t.Fatal("expected error")
			}
			if reason := publicReason(err); reason != tc.reason {
				t.Fatalf("reason = %q, want %q", reason, tc.reason)
			}
		})
	}
}
