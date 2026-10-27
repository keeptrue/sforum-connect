package main

import (
	"errors"
	"regexp"
	"strings"
)

// 稳定错误码。Host 只把 Reason 当作公开映射键；Message 必须已脱敏。
const (
	reasonConfigMissing         = "sforum.config_missing"
	reasonBaseURLInvalid        = "sforum.base_url_invalid"
	reasonBaseURLInsecure       = "sforum.base_url_insecure"
	reasonCredentialsMissing    = "sforum.credentials_missing"
	reasonClientIDMissing       = "sforum.client_id_missing"
	reasonClientSecretMissing   = "sforum.client_secret_missing"
	reasonStartInputInvalid     = "sforum.start_input_invalid"
	reasonPKCEMethodUnsupported = "sforum.pkce_method_unsupported"
	reasonCallbackInvalid       = "sforum.callback_invalid"
	reasonCompleteInputInvalid  = "sforum.complete_input_invalid"
	reasonTokenUnreachable      = "sforum.token_unreachable"
	reasonTokenClientRejected   = "sforum.token_client_rejected"
	reasonTokenGrantRejected    = "sforum.token_grant_rejected"
	reasonTokenScopeRejected    = "sforum.token_scope_rejected"
	reasonTokenServerError      = "sforum.token_server_error"
	reasonTokenExchangeFailed   = "sforum.token_exchange_failed"
	reasonTokenMalformed        = "sforum.token_malformed"
	reasonTokenEmpty            = "sforum.token_empty"
	reasonTimeout               = "sforum.timeout"
	reasonUserUnauthorized      = "sforum.user_unauthorized"
	reasonUserRequestInvalid    = "sforum.user_request_invalid"
	reasonUserServerError       = "sforum.user_server_error"
	reasonUserFetchFailed       = "sforum.user_fetch_failed"
	reasonUserUnreachable       = "sforum.user_unreachable"
	reasonUserMalformed         = "sforum.user_malformed"
	reasonSubjectMissing        = "sforum.subject_missing"
	reasonProbeOK               = "sforum.probe_ok"
	reasonDocsMalformed         = "sforum.docs_malformed"
	reasonProviderMissing       = "sforum.provider_missing"
	reasonEndpointUnreachable   = "sforum.endpoint_unreachable"
	reasonEndpointError         = "sforum.endpoint_error"
	reasonInternal              = "sforum.internal_error"
)

// 敏感材料匹配：令牌、密钥、授权码与 verifier 不得进入错误消息或日志。
var (
	redactBearer   = regexp.MustCompile(`(?i)bearer\s+[a-z0-9._\-+/=]{8,}`)
	redactKVSecret = regexp.MustCompile(`(?i)(client_secret|access_token|refresh_token|code_verifier|code)=([^\s&,"']+)`)
	redactLongHex  = regexp.MustCompile(`\b[a-f0-9]{32,}\b`)
)

// RedactSensitive 擦除诊断字符串中的密钥、令牌与类凭证材料。
func RedactSensitive(message string) string {
	if message == "" {
		return message
	}
	out := redactBearer.ReplaceAllString(message, "bearer [redacted]")
	out = redactKVSecret.ReplaceAllString(out, "$1=[redacted]")
	out = redactLongHex.ReplaceAllString(out, "[redacted]")
	return out
}

// ErrPublic 是可安全返回给 Host 的协议错误（已脱敏）。
type ErrPublic struct {
	Reason  string
	Message string
}

func (e *ErrPublic) Error() string {
	if e == nil {
		return "sforum connect error"
	}
	if e.Message != "" {
		return e.Message
	}
	return e.Reason
}

func publicErr(reason, message string) error {
	return &ErrPublic{Reason: reason, Message: RedactSensitive(message)}
}

// publicReason 提取稳定错误码；未知错误一律收敛到内部错误码，避免把
// 第三方/标准库的错误文本当作公开契约。
func publicReason(err error) string {
	var pub *ErrPublic
	if errors.As(err, &pub) && strings.TrimSpace(pub.Reason) != "" {
		return pub.Reason
	}
	return reasonInternal
}

// publicMessage 返回已脱敏的错误文案。
func publicMessage(err error) string {
	if err == nil {
		return ""
	}
	var pub *ErrPublic
	if errors.As(err, &pub) && strings.TrimSpace(pub.Message) != "" {
		return RedactSensitive(pub.Message)
	}
	return "the SForum OAuth2 request failed"
}
