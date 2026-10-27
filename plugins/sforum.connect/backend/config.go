package main

import (
	"os"
	"strings"
	"time"
)

// Host 把设置文档里的字段以 SFORUM_SETTING_<KEY> 注入插件进程。
const (
	settingBaseURL      = "SFORUM_SETTING_BASE_URL"
	settingClientID     = "SFORUM_SETTING_CLIENT_ID"
	settingClientSecret = "SFORUM_SETTING_CLIENT_SECRET"
)

const (
	defaultHTTPTimeout = 8 * time.Second
	// 响应体上限：令牌与用户资料都是小 JSON，超出即视为异常响应。
	maxResponseBytes = 1 << 20
	maxProbeBytes    = 256 << 10
	userAgent        = "sforum-connect/1.0"
)

// Config 是插件进程内的 OAuth2 客户端配置。client_secret 只来自 Host 注入的
// 设置环境变量（SecretStore），永不进入浏览器、日志或错误消息。
type Config struct {
	BaseURL      string
	BaseURLErr   error
	ClientID     string
	ClientSecret string
	Endpoints    Endpoints
	HTTPTimeout  time.Duration
}

// NewConfig 归一化 base URL 并派生端点。base URL 非法时保留错误，
// 让每个操作与探测都 fail closed 并给出同一个稳定原因。
func NewConfig(rawBaseURL, clientID, clientSecret string) Config {
	cfg := Config{
		ClientID:     strings.TrimSpace(clientID),
		ClientSecret: strings.TrimSpace(clientSecret),
		HTTPTimeout:  defaultHTTPTimeout,
	}
	base, err := NormalizeBaseURL(rawBaseURL)
	if err != nil {
		cfg.BaseURLErr = err
		return cfg
	}
	cfg.BaseURL = base
	cfg.Endpoints = EndpointsFor(base)
	return cfg
}

// LoadConfigFromEnv 从 Host 注入的设置加载配置。
// 空 base URL 回落默认官方站：Host 尚未写入设置时也不至于整条链路不可用。
func LoadConfigFromEnv() Config {
	return NewConfig(
		os.Getenv(settingBaseURL),
		os.Getenv(settingClientID),
		os.Getenv(settingClientSecret),
	)
}

// CredentialsPresent 判断启动 OAuth 所需的凭证是否齐全。
func (c Config) CredentialsPresent() bool {
	return c.ClientID != "" && c.ClientSecret != ""
}

// Ready 返回当前配置是否足以发起一次授权/兑换。
func (c Config) Ready() error {
	if c.BaseURLErr != nil {
		return c.BaseURLErr
	}
	if !c.CredentialsPresent() {
		return publicErr(reasonCredentialsMissing, "client_id and client_secret are required")
	}
	return nil
}
