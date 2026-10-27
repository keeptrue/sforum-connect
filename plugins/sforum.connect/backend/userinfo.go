package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// IdentityAssertion 是插件返回给 Host 的有界外部主体断言。
// 不含 digest、access token 或任何 Host 会话材料。
type IdentityAssertion struct {
	ProviderSubject string
	UsernameHint    string
	DisplayName     string
	EmailHint       string
	EmailVerified   bool
}

type remoteProfile struct {
	Sub           string `json:"sub"`
	ID            any    `json:"id"`
	Username      string `json:"username"`
	DisplayName   string `json:"displayName"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"emailVerified"`
}

// CompleteIdentity 用授权码换令牌、读取用户资料，并返回主体断言。
// 访问令牌只在这条调用栈里存在，函数返回后即失去引用。
func (o *SForumOAuth) CompleteIdentity(ctx context.Context, code, codeVerifier, callbackURL string) (IdentityAssertion, error) {
	accessToken, err := o.exchangeCode(ctx, code, codeVerifier, callbackURL)
	if err != nil {
		return IdentityAssertion{}, err
	}
	profile, err := o.fetchProfile(ctx, accessToken)
	if err != nil {
		return IdentityAssertion{}, err
	}
	return assertionFromProfile(profile)
}

// fetchProfile 读取远端 userinfo。
//
// SForum 的 userinfo 只认 access_token 查询参数：宿主会在插件路由前剥掉
// Authorization 头，Bearer 头到不了插件。这里按它的公开契约调用。
func (o *SForumOAuth) fetchProfile(ctx context.Context, accessToken string) (remoteProfile, error) {
	if err := o.ready(); err != nil {
		return remoteProfile{}, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	accessToken = strings.TrimSpace(accessToken)
	if accessToken == "" {
		return remoteProfile{}, publicErr(reasonTokenEmpty, "access_token is required")
	}

	endpoint, err := url.Parse(o.Config.Endpoints.Userinfo)
	if err != nil {
		return remoteProfile{}, publicErr(reasonConfigMissing, "the userinfo endpoint is not configured")
	}
	query := endpoint.Query()
	query.Set("access_token", accessToken)
	endpoint.RawQuery = query.Encode()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return remoteProfile{}, publicErr(reasonUserFetchFailed, "failed to build the userinfo request")
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)

	response, err := o.HTTPClient.Do(request)
	if err != nil {
		// 错误里可能带完整 URL（含令牌），因此只返回稳定原因。
		return remoteProfile{}, mapTransportError(err, reasonUserUnreachable)
	}
	defer response.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes))
	if readErr != nil {
		return remoteProfile{}, publicErr(reasonUserFetchFailed, "failed to read the userinfo response")
	}
	switch {
	case response.StatusCode == http.StatusUnauthorized:
		return remoteProfile{}, publicErr(reasonUserUnauthorized, "the site rejected the access token")
	case response.StatusCode == http.StatusBadRequest:
		return remoteProfile{}, publicErr(reasonUserRequestInvalid, "the userinfo request was rejected as invalid")
	case response.StatusCode >= 500:
		return remoteProfile{}, publicErr(reasonUserServerError, "the site reported a server error for userinfo")
	case response.StatusCode < 200 || response.StatusCode >= 300:
		return remoteProfile{}, publicErr(reasonUserFetchFailed,
			fmt.Sprintf("the userinfo endpoint returned status %d", response.StatusCode))
	}

	// UseNumber 保留远端 id 的十进制精度：float64 在超过 2^53 后会丢位。
	var profile remoteProfile
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&profile); err != nil {
		return remoteProfile{}, publicErr(reasonUserMalformed, "the userinfo response was not valid JSON")
	}
	return profile, nil
}

// assertionFromProfile 把远端资料裁剪成 Host 接受的有界断言。
//
// 邮箱只在远端明确标记为已验证时下发：未验证邮箱作为注册提示会让人用
// 别人的地址预填表单。
func assertionFromProfile(profile remoteProfile) (IdentityAssertion, error) {
	subject := strings.TrimSpace(profile.Sub)
	if subject == "" {
		subject = decimalID(profile.ID)
	}
	if subject == "" {
		return IdentityAssertion{}, publicErr(reasonSubjectMissing, "the userinfo response did not include a stable subject")
	}
	if len(subject) > 320 {
		subject = subject[:320]
	}

	username := strings.TrimSpace(profile.Username)
	if len(username) > 64 {
		username = username[:64]
	}
	display := strings.TrimSpace(profile.DisplayName)
	if display == "" {
		display = username
	}
	if len(display) > 200 {
		display = display[:200]
	}

	email := strings.ToLower(strings.TrimSpace(profile.Email))
	verified := profile.EmailVerified && email != ""
	if !verified {
		email = ""
	}
	if len(email) > 320 {
		email = email[:320]
	}

	return IdentityAssertion{
		ProviderSubject: subject,
		UsernameHint:    username,
		DisplayName:     display,
		EmailHint:       email,
		EmailVerified:   verified,
	}, nil
}

// decimalID 接受数字或纯数字字符串形态的 id，拒绝小数与其它类型。
func decimalID(value any) string {
	switch typed := value.(type) {
	case float64:
		if typed <= 0 || typed != math.Trunc(typed) || typed > math.MaxInt64 {
			return ""
		}
		return strconv.FormatInt(int64(typed), 10)
	case json.Number:
		text := typed.String()
		if _, err := strconv.ParseInt(text, 10, 64); err != nil {
			return ""
		}
		return text
	case string:
		trimmed := strings.TrimSpace(typed)
		if trimmed == "" {
			return ""
		}
		for _, char := range trimmed {
			if char < '0' || char > '9' {
				return ""
			}
		}
		return trimmed
	default:
		return ""
	}
}
