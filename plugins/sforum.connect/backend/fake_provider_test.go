package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"
)

// fakeProvider 是协议级单测用的本地 SForum OAuth2 替身。
// 覆盖 docs / authorize / token（含 PKCE S256 校验）/ userinfo 与故障注入。
type fakeProvider struct {
	Server *httptest.Server

	ClientID     string
	ClientSecret string
	AccessToken  string
	RedirectURI  string
	Profile      map[string]any

	// 故障注入
	DocsStatus      int
	DocsBody        string
	AuthorizeStatus int
	TokenStatus     int
	TokenBody       string
	TokenRedirect   string
	TokenDelay      time.Duration
	CSRFStatus      int
	CSRFBody        string
	RequireCSRF     bool
	UserinfoStatus  int
	UserinfoBody    string

	mu            sync.Mutex
	challenges    map[string]string
	lastAuthorize url.Values
	lastToken     map[string]any
	lastUserinfo  url.Values
	tokenCalls    int
	userinfoCalls int
	csrfCalls     int
	issuedCSRF    string
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	fake := &fakeProvider{
		ClientID:     "sfo_client_test",
		ClientSecret: "sfos_test_secret",
		AccessToken:  "sfoa_test_token",
		RedirectURI:  "https://site.example/auth/providers/sforum.connect.auth/callback",
		Profile: map[string]any{
			"sub":           "42",
			"id":            42,
			"username":      "alice",
			"displayName":   "Alice",
			"email":         "Alice@Example.com",
			"emailVerified": true,
		},
		challenges:  map[string]string{},
		RequireCSRF: true,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/oauth/docs", fake.handleDocs)
	mux.HandleFunc("/api/oauth/csrf", fake.handleCSRF)
	mux.HandleFunc("/api/oauth/authorize", fake.handleAuthorize)
	mux.HandleFunc("/api/oauth/token", fake.handleToken)
	mux.HandleFunc("/api/oauth/userinfo", fake.handleUserinfo)
	fake.Server = httptest.NewServer(mux)
	t.Cleanup(fake.Server.Close)
	return fake
}

func (f *fakeProvider) config() Config {
	return NewConfig(f.Server.URL, f.ClientID, f.ClientSecret)
}

// IssueCode 颁发一个授权码并登记它的 PKCE challenge（空表示不校验 PKCE）。
func (f *fakeProvider) IssueCode(challenge string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	code := fmt.Sprintf("sfoc_test_%d", len(f.challenges)+1)
	f.challenges[code] = challenge
	return code
}

func (f *fakeProvider) LastAuthorizeQuery() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastAuthorize
}

func (f *fakeProvider) LastTokenBody() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastToken
}

func (f *fakeProvider) CSRFCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.csrfCalls
}

func (f *fakeProvider) LastUserinfoQuery() url.Values {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastUserinfo
}

func (f *fakeProvider) TokenCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.tokenCalls
}

func (f *fakeProvider) UserinfoCalls() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.userinfoCalls
}

func (f *fakeProvider) handleDocs(w http.ResponseWriter, _ *http.Request) {
	if f.DocsStatus != 0 {
		w.WriteHeader(f.DocsStatus)
		_, _ = w.Write([]byte(f.DocsBody))
		return
	}
	body := f.DocsBody
	if body == "" {
		body = `{"ok":true,"endpoints":[{"path":"/api/oauth/authorize"},{"path":"/api/oauth/token"},{"path":"/api/oauth/userinfo"}]}`
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(body))
}

func (f *fakeProvider) handleCSRF(w http.ResponseWriter, _ *http.Request) {
	f.mu.Lock()
	f.csrfCalls++
	if f.RequireCSRF {
		f.issuedCSRF = fmt.Sprintf("csrf_test_%d", f.csrfCalls)
	}
	issued := f.issuedCSRF
	f.mu.Unlock()

	if f.CSRFStatus != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.CSRFStatus)
		_, _ = w.Write([]byte(f.CSRFBody))
		return
	}
	if issued != "" {
		http.SetCookie(w, &http.Cookie{Name: "csrf_", Value: issued, Path: "/", HttpOnly: true})
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(`{"ok":true,"csrfRequired":true}`))
}

func (f *fakeProvider) handleAuthorize(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.lastAuthorize = r.URL.Query()
	f.mu.Unlock()
	status := f.AuthorizeStatus
	if status == 0 {
		status = http.StatusBadRequest
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`{"error":"invalid_request","error_description":"authorization request is incomplete"}`))
}

func (f *fakeProvider) handleToken(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	f.lastToken = body
	f.tokenCalls++
	requireCSRF := f.RequireCSRF
	issuedCSRF := f.issuedCSRF
	f.mu.Unlock()

	if requireCSRF {
		cookie, _ := r.Cookie("csrf_")
		header := r.Header.Get("X-Csrf-Token")
		if cookie == nil || cookie.Value == "" || header != cookie.Value || header != issuedCSRF {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"code":403,"message":"请求校验失败","data":{"reason":"csrf.invalid"}}`))
			return
		}
	}

	if f.TokenDelay > 0 {
		time.Sleep(f.TokenDelay)
	}
	if f.TokenRedirect != "" {
		http.Redirect(w, r, f.TokenRedirect, http.StatusFound)
		return
	}
	if f.TokenStatus != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.TokenStatus)
		_, _ = w.Write([]byte(f.TokenBody))
		return
	}
	if f.TokenBody != "" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(f.TokenBody))
		return
	}

	if bodyString(body, "grant_type") != "authorization_code" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request")
		return
	}
	if bodyString(body, "client_id") != f.ClientID || bodyString(body, "client_secret") != f.ClientSecret {
		writeOAuthError(w, http.StatusUnauthorized, "invalid_client")
		return
	}
	if bodyString(body, "redirect_uri") != f.RedirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	code := bodyString(body, "code")
	f.mu.Lock()
	challenge, known := f.challenges[code]
	f.mu.Unlock()
	if !known {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant")
		return
	}
	if challenge != "" {
		verifier := bodyString(body, "code_verifier")
		if verifier == "" || s256(verifier) != challenge {
			writeOAuthError(w, http.StatusBadRequest, "invalid_grant")
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token": f.AccessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        "profile email",
	})
}

func (f *fakeProvider) handleUserinfo(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.lastUserinfo = r.URL.Query()
	f.userinfoCalls++
	f.mu.Unlock()

	if f.UserinfoStatus != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(f.UserinfoStatus)
		_, _ = w.Write([]byte(f.UserinfoBody))
		return
	}
	if f.UserinfoBody != "" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(f.UserinfoBody))
		return
	}
	if r.URL.Query().Get("access_token") != f.AccessToken {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_token"}`))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(f.Profile)
}

func bodyString(values map[string]any, key string) string {
	text, _ := values[key].(string)
	return text
}

func writeOAuthError(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(fmt.Sprintf(`{"error":%q,"error_description":"rejected"}`, code)))
}

func s256(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
