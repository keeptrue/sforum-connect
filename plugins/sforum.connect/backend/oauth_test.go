package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const testCallback = "https://site.example/auth/providers/sforum.connect.auth/callback"

func TestBuildAuthorizeURL(t *testing.T) {
	oauth := NewSForumOAuth(NewConfig("https://bbs.dalao.me", "sfo_client_x", "sfos_y"), nil)
	raw, err := oauth.BuildAuthorizeURL("state-1", "challenge-1", testCallback)
	if err != nil {
		t.Fatalf("build authorize URL: %v", err)
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.Host != "bbs.dalao.me" || parsed.Path != "/api/oauth/authorize" {
		t.Fatalf("unexpected endpoint: %s", raw)
	}
	query := parsed.Query()
	if query.Get("response_type") != "code" {
		t.Fatalf("response_type = %q", query.Get("response_type"))
	}
	if query.Get("client_id") != "sfo_client_x" {
		t.Fatalf("client_id = %q", query.Get("client_id"))
	}
	if query.Get("redirect_uri") != testCallback {
		t.Fatalf("redirect_uri = %q", query.Get("redirect_uri"))
	}
	if query.Get("state") != "state-1" || query.Get("code_challenge") != "challenge-1" {
		t.Fatalf("state/challenge missing: %v", query)
	}
	if query.Get("code_challenge_method") != "S256" {
		t.Fatalf("code_challenge_method = %q", query.Get("code_challenge_method"))
	}
	// 关键契约：不发送 scope，由站点按应用登记范围授权。
	if _, present := query["scope"]; present {
		t.Fatalf("authorize URL must not send scope: %s", raw)
	}
}

func TestBuildAuthorizeURLRejectsMissingInput(t *testing.T) {
	oauth := NewSForumOAuth(NewConfig("https://bbs.dalao.me", "id", "secret"), nil)
	cases := []struct {
		name      string
		state     string
		challenge string
		callback  string
		reason    string
	}{
		{"missing state", "", "challenge", testCallback, reasonStartInputInvalid},
		{"missing challenge", "state", "", testCallback, reasonStartInputInvalid},
		{"missing callback", "state", "challenge", "", reasonStartInputInvalid},
		{"relative callback", "state", "challenge", "/callback", reasonCallbackInvalid},
		{"unsupported callback scheme", "state", "challenge", "javascript:alert(1)", reasonCallbackInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := oauth.BuildAuthorizeURL(tc.state, tc.challenge, tc.callback)
			if err == nil {
				t.Fatal("expected error")
			}
			if reason := publicReason(err); reason != tc.reason {
				t.Fatalf("reason = %q, want %q", reason, tc.reason)
			}
		})
	}
}

func TestBuildAuthorizeURLRequiresCredentials(t *testing.T) {
	oauth := NewSForumOAuth(NewConfig("https://bbs.dalao.me", "", ""), nil)
	_, err := oauth.BuildAuthorizeURL("state", "challenge", testCallback)
	if reason := publicReason(err); reason != reasonCredentialsMissing {
		t.Fatalf("reason = %q", reason)
	}
}

func TestExchangeCodeSuccess(t *testing.T) {
	fake := newFakeProvider(t)
	oauth := NewSForumOAuth(fake.config(), nil)
	verifier := "verifier-abcdefghijklmnopqrstuvwxyz-0123456789"
	code := fake.IssueCode(s256(verifier))

	token, err := oauth.exchangeCode(context.Background(), code, verifier, fake.RedirectURI)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if token != fake.AccessToken {
		t.Fatalf("token = %q", token)
	}
	body := fake.LastTokenBody()
	if bodyString(body, "grant_type") != "authorization_code" {
		t.Fatalf("grant_type = %q", bodyString(body, "grant_type"))
	}
	if bodyString(body, "code") != code || bodyString(body, "code_verifier") != verifier {
		t.Fatalf("code/verifier missing: %v", body)
	}
	if bodyString(body, "redirect_uri") != fake.RedirectURI {
		t.Fatalf("redirect_uri = %q", bodyString(body, "redirect_uri"))
	}
	if bodyString(body, "client_secret") != fake.ClientSecret {
		t.Fatal("client_secret missing from the token body")
	}
	if fake.CSRFCalls() == 0 {
		t.Fatal("the CSRF handshake must run before the token exchange")
	}
}

func TestExchangeCodeWithoutVerifier(t *testing.T) {
	fake := newFakeProvider(t)
	oauth := NewSForumOAuth(fake.config(), nil)
	code := fake.IssueCode("")

	if _, err := oauth.exchangeCode(context.Background(), code, "", fake.RedirectURI); err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if _, present := fake.LastTokenBody()["code_verifier"]; present {
		t.Fatal("empty verifier must not be sent")
	}
}

func TestExchangeCodeWithoutCSRFEndpoint(t *testing.T) {
	fake := newFakeProvider(t)
	fake.RequireCSRF = false
	fake.CSRFStatus = http.StatusNotFound
	fake.CSRFBody = "not found"
	oauth := NewSForumOAuth(fake.config(), nil)
	code := fake.IssueCode("")

	if _, err := oauth.exchangeCode(context.Background(), code, "", fake.RedirectURI); err != nil {
		t.Fatalf("exchange: %v", err)
	}
}

func TestExchangeCodeFailsWhenCSRFHandshakeFails(t *testing.T) {
	fake := newFakeProvider(t)
	fake.CSRFStatus = http.StatusInternalServerError
	fake.CSRFBody = "{}"
	oauth := NewSForumOAuth(fake.config(), nil)
	code := fake.IssueCode("")

	_, err := oauth.exchangeCode(context.Background(), code, "", fake.RedirectURI)
	if reason := publicReason(err); reason != reasonTokenExchangeFailed {
		t.Fatalf("reason = %q", reason)
	}
	if fake.TokenCalls() != 0 {
		t.Fatal("no token request should be sent when the handshake fails")
	}
}

func TestExchangeCodeErrors(t *testing.T) {
	cases := []struct {
		name   string
		setup  func(*fakeProvider)
		code   string
		reason string
	}{
		{
			name:   "wrong secret",
			setup:  func(f *fakeProvider) { f.ClientSecret = "sfos_rotated" },
			reason: reasonTokenClientRejected,
		},
		{
			name:   "unknown code",
			setup:  func(*fakeProvider) {},
			code:   "sfoc_missing",
			reason: reasonTokenGrantRejected,
		},
		{
			name: "invalid scope",
			setup: func(f *fakeProvider) {
				f.TokenStatus = http.StatusBadRequest
				f.TokenBody = `{"error":"invalid_scope"}`
			},
			reason: reasonTokenScopeRejected,
		},
		{
			name: "server error",
			setup: func(f *fakeProvider) {
				f.TokenStatus = http.StatusInternalServerError
				f.TokenBody = `{"error":"server_error"}`
			},
			reason: reasonTokenServerError,
		},
		{
			name: "malformed body",
			setup: func(f *fakeProvider) {
				f.TokenStatus = http.StatusOK
				f.TokenBody = "<html>not json</html>"
			},
			reason: reasonTokenMalformed,
		},
		{
			name: "empty token",
			setup: func(f *fakeProvider) {
				f.TokenStatus = http.StatusOK
				f.TokenBody = `{"token_type":"Bearer"}`
			},
			reason: reasonTokenMalformed,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := newFakeProvider(t)
			oauth := NewSForumOAuth(fake.config(), nil)
			code := tc.code
			if code == "" {
				code = fake.IssueCode("")
			}
			tc.setup(fake)
			_, err := oauth.exchangeCode(context.Background(), code, "", fake.RedirectURI)
			if err == nil {
				t.Fatal("expected error")
			}
			if reason := publicReason(err); reason != tc.reason {
				t.Fatalf("reason = %q, want %q (%v)", reason, tc.reason, err)
			}
		})
	}
}

func TestExchangeCodeTimeout(t *testing.T) {
	fake := newFakeProvider(t)
	fake.TokenDelay = 300 * time.Millisecond
	oauth := NewSForumOAuth(fake.config(), &http.Client{Timeout: 50 * time.Millisecond})
	code := fake.IssueCode("")

	_, err := oauth.exchangeCode(context.Background(), code, "", fake.RedirectURI)
	if reason := publicReason(err); reason != reasonTimeout {
		t.Fatalf("reason = %q", reason)
	}
}

func TestExchangeCodeDoesNotFollowRedirects(t *testing.T) {
	fake := newFakeProvider(t)
	var hits int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer other.Close()
	fake.TokenRedirect = other.URL
	oauth := NewSForumOAuth(fake.config(), nil)
	code := fake.IssueCode("")

	_, err := oauth.exchangeCode(context.Background(), code, "", fake.RedirectURI)
	if err == nil {
		t.Fatal("expected error")
	}
	if reason := publicReason(err); reason != reasonTokenExchangeFailed {
		t.Fatalf("reason = %q", reason)
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("redirect target received %d requests", got)
	}
}

func TestExchangeCodeAcceptsFormEncodedToken(t *testing.T) {
	fake := newFakeProvider(t)
	fake.TokenStatus = http.StatusOK
	fake.TokenBody = "access_token=sfoa_form&token_type=Bearer"
	oauth := NewSForumOAuth(fake.config(), nil)
	code := fake.IssueCode("")

	token, err := oauth.exchangeCode(context.Background(), code, "", fake.RedirectURI)
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if token != "sfoa_form" {
		t.Fatalf("token = %q", token)
	}
}

func TestExchangeCodeRejectsMissingInput(t *testing.T) {
	fake := newFakeProvider(t)
	oauth := NewSForumOAuth(fake.config(), nil)
	_, err := oauth.exchangeCode(context.Background(), "", "", fake.RedirectURI)
	if reason := publicReason(err); reason != reasonCompleteInputInvalid {
		t.Fatalf("reason = %q", reason)
	}
	if fake.TokenCalls() != 0 {
		t.Fatal("no token request should be sent")
	}
}

func TestErrorMessagesNeverContainSecrets(t *testing.T) {
	fake := newFakeProvider(t)
	oauth := NewSForumOAuth(fake.config(), nil)
	// 配置读入后再轮换密钥：客户端仍拿旧密钥，服务端必然拒绝。
	fake.ClientSecret = "sfos_rotated_secret"
	code := fake.IssueCode("")
	_, err := oauth.exchangeCode(context.Background(), code, "", fake.RedirectURI)
	if err == nil {
		t.Fatal("expected error")
	}
	message := strings.ToLower(publicMessage(err))
	for _, needle := range []string{"sfos_", "sfoa_", "sfoc_", "verifier"} {
		if strings.Contains(message, needle) {
			t.Fatalf("message leaked %q: %s", needle, message)
		}
	}
}
