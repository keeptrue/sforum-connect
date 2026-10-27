package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// SForumOAuth 封装 Authorization Code + PKCE S256 协议。
// 它不拥有 state、回调事务或会话；只使用 Host 注入的材料与远端站点通信，
// 并在身份证明完成后立即丢弃访问令牌。
type SForumOAuth struct {
	Config     Config
	HTTPClient *http.Client
}

// NewSForumOAuth 构造协议客户端。httpClient 可为 nil（使用带超时且不跟随
// 重定向的默认客户端）。
func NewSForumOAuth(cfg Config, httpClient *http.Client) *SForumOAuth {
	if httpClient == nil {
		httpClient = newBoundedHTTPClient(cfg.HTTPTimeout)
	}
	return &SForumOAuth{Config: cfg, HTTPClient: httpClient}
}

// newBoundedHTTPClient 禁止跟随重定向：token 端点若 302 到别的主机，
// 跟随会把 client_secret 交给重定向目标。
func newBoundedHTTPClient(timeout time.Duration) *http.Client {
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func (o *SForumOAuth) ready() error {
	if o == nil {
		return publicErr(reasonConfigMissing, "the SForum OAuth2 client is not configured")
	}
	return o.Config.Ready()
}

// BuildAuthorizeURL 使用 Host 拥有的 state / PKCE challenge / callbackURL
// 构造远端授权 URL。
//
// 不发送 scope：SForum 的授权端点在省略 scope 时回落到「应用登记的权限范围」，
// 这样应用在站点上勾了什么就授权什么，不会因为应用没登记 email 而 invalid_scope。
func (o *SForumOAuth) BuildAuthorizeURL(state, codeChallenge, callbackURL string) (string, error) {
	if err := o.ready(); err != nil {
		return "", err
	}
	state = strings.TrimSpace(state)
	codeChallenge = strings.TrimSpace(codeChallenge)
	callbackURL = strings.TrimSpace(callbackURL)
	if state == "" || codeChallenge == "" || callbackURL == "" {
		return "", publicErr(reasonStartInputInvalid, "state, codeChallenge, and callbackUrl are required")
	}
	if err := requireAbsoluteCallback(callbackURL); err != nil {
		return "", err
	}

	query := url.Values{}
	query.Set("response_type", "code")
	query.Set("client_id", o.Config.ClientID)
	query.Set("redirect_uri", callbackURL)
	query.Set("state", state)
	query.Set("code_challenge", codeChallenge)
	query.Set("code_challenge_method", "S256")

	authorizeURL := o.Config.Endpoints.Authorize
	if strings.TrimSpace(authorizeURL) == "" {
		return "", publicErr(reasonConfigMissing, "the authorize endpoint is not configured")
	}
	return authorizeURL + "?" + query.Encode(), nil
}

// exchangeCode 用授权码换访问令牌。返回值只允许在 CompleteIdentity 内部使用。
func (o *SForumOAuth) exchangeCode(ctx context.Context, code, codeVerifier, callbackURL string) (string, error) {
	if err := o.ready(); err != nil {
		return "", err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	code = strings.TrimSpace(code)
	callbackURL = strings.TrimSpace(callbackURL)
	if code == "" || callbackURL == "" {
		return "", publicErr(reasonCompleteInputInvalid, "completionToken and callbackUrl are required")
	}
	if err := requireAbsoluteCallback(callbackURL); err != nil {
		return "", err
	}

	// SForum 的 token 路由声明了请求 schema，Host 只把 JSON 体解析成文档；
	// form-encoded 会被判 extensions.route_schema_invalid（422）。
	tokenRequest := map[string]any{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  callbackURL,
		"client_id":     o.Config.ClientID,
		"client_secret": o.Config.ClientSecret,
	}
	if verifier := strings.TrimSpace(codeVerifier); verifier != "" {
		tokenRequest["code_verifier"] = verifier
	}
	encoded, err := json.Marshal(tokenRequest)
	if err != nil {
		return "", publicErr(reasonTokenExchangeFailed, "failed to encode the token request")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, o.Config.Endpoints.Token, bytes.NewReader(encoded))
	if err != nil {
		return "", publicErr(reasonTokenExchangeFailed, "failed to build the token request")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)

	// public unsafe 路由要求 CSRF 双提交：cookie 值必须与 X-Csrf-Token 相同。
	// 旧版 provider 没有握手端点时返回 404，按无 CSRF 继续。
	csrf, err := o.fetchCSRFToken(ctx)
	if err != nil {
		return "", err
	}
	if csrf != "" {
		request.Header.Set("Cookie", "csrf_="+csrf)
		request.Header.Set("X-Csrf-Token", csrf)
	}

	response, err := o.HTTPClient.Do(request)
	if err != nil {
		return "", mapTransportError(err, reasonTokenUnreachable)
	}
	defer response.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if readErr != nil {
		return "", publicErr(reasonTokenExchangeFailed, "failed to read the token response")
	}
	// 客户端禁止跟随重定向；这里显式拒绝 3xx，避免把重定向目标当成令牌响应。
	if response.StatusCode >= 300 && response.StatusCode < 400 {
		return "", publicErr(reasonTokenExchangeFailed, "the token endpoint redirected instead of returning a token")
	}
	payload, parseErr := parseTokenBody(body)
	if parseErr != nil {
		return "", parseErr
	}
	if payload.Error != "" {
		return "", mapOAuthError(payload.Error)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", publicErr(reasonTokenExchangeFailed,
			fmt.Sprintf("the token endpoint returned status %d", response.StatusCode))
	}
	token := strings.TrimSpace(payload.AccessToken)
	if token == "" {
		return "", publicErr(reasonTokenEmpty, "the token response did not include access_token")
	}
	return token, nil
}

// fetchCSRFToken 完成 SForum 的 CSRF 握手：GET /api/oauth/csrf 会种下 csrf_ cookie。
// 返回空字符串表示该站点没有握手端点（旧版本），调用方按无 CSRF 继续。
func (o *SForumOAuth) fetchCSRFToken(ctx context.Context) (string, error) {
	endpoint := strings.TrimSpace(o.Config.Endpoints.CSRF)
	if endpoint == "" {
		return "", nil
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", publicErr(reasonTokenExchangeFailed, "failed to build the CSRF handshake request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)

	response, err := o.HTTPClient.Do(request)
	if err != nil {
		return "", mapTransportError(err, reasonTokenUnreachable)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, maxProbeBytes))

	if response.StatusCode == http.StatusNotFound {
		return "", nil
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", publicErr(reasonTokenExchangeFailed, "the CSRF handshake was rejected")
	}
	for _, cookie := range response.Cookies() {
		if cookie.Name == "csrf_" && cookie.Value != "" {
			return cookie.Value, nil
		}
	}
	return "", publicErr(reasonTokenExchangeFailed, "the CSRF handshake did not set a csrf cookie")
}

type tokenPayload struct {
	AccessToken      string `json:"access_token"`
	TokenType        string `json:"token_type"`
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// parseTokenBody 先按 JSON 解析；兼容只返回表单编码的旧实现。
func parseTokenBody(body []byte) (tokenPayload, error) {
	var payload tokenPayload
	if err := json.Unmarshal(body, &payload); err == nil &&
		(payload.AccessToken != "" || payload.Error != "") {
		return payload, nil
	}
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return tokenPayload{}, publicErr(reasonTokenMalformed, "the token response was not valid JSON or form encoding")
	}
	payload.AccessToken = values.Get("access_token")
	payload.TokenType = values.Get("token_type")
	payload.Error = values.Get("error")
	payload.ErrorDescription = values.Get("error_description")
	if payload.AccessToken == "" && payload.Error == "" {
		return tokenPayload{}, publicErr(reasonTokenMalformed, "the token response did not include a token or an error")
	}
	return payload, nil
}

// mapOAuthError 把远端 error 码映射成稳定原因；不回传 error_description，
// 避免把远端诊断文本（可能含标识符）当成公开契约。
func mapOAuthError(code string) error {
	switch strings.ToLower(strings.TrimSpace(code)) {
	case "invalid_client":
		return publicErr(reasonTokenClientRejected, "the site rejected client_id or client_secret")
	case "invalid_grant":
		return publicErr(reasonTokenGrantRejected, "the site rejected the authorization code or the PKCE verifier")
	case "invalid_scope":
		return publicErr(reasonTokenScopeRejected, "the requested scope exceeds the app's registered scopes")
	case "invalid_request":
		return publicErr(reasonTokenExchangeFailed, "the token request was rejected as invalid")
	case "server_error":
		return publicErr(reasonTokenServerError, "the site reported a server error during the token exchange")
	default:
		return publicErr(reasonTokenExchangeFailed, "the site rejected the token exchange")
	}
}

func mapTransportError(err error, unreachableReason string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return publicErr(reasonTimeout, "the request to the site timed out")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return publicErr(reasonTimeout, "the request to the site timed out")
	}
	return publicErr(unreachableReason, "the request to the site failed")
}

// requireAbsoluteCallback 拒绝相对路径与无 scheme 的 callback。
// Host 注入的是可信站点绝对地址；这里再做一层纵深防御。
func requireAbsoluteCallback(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return publicErr(reasonCallbackInvalid, "callbackUrl must be an absolute URL")
	}
	switch strings.ToLower(parsed.Scheme) {
	case "https", "http":
		return nil
	default:
		return publicErr(reasonCallbackInvalid, "callbackUrl must use http or https")
	}
}
