package main

import (
	"net"
	"net/url"
	pathpkg "path"
	"strings"
)

// defaultBaseURL 是官方站的默认根地址。操作者可以在设置里改成任意
// SForum 站点（包括自建的、带路径前缀的部署）。
const defaultBaseURL = "https://bbs.dalao.me"

// Endpoints 由 base URL 派生，避免让操作者分别填三个地址。
type Endpoints struct {
	Authorize string
	Token     string
	Userinfo  string
	Docs      string
	CSRF      string
}

// NormalizeBaseURL 校验并归一化站点根地址。
//
// 规则与 SForum OAuth2 Provider 自己的回调策略一致：非 loopback 必须 https；
// loopback（localhost / 127.0.0.1 / ::1）允许 http，方便本地联调。
func NormalizeBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		raw = defaultBaseURL
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", publicErr(reasonBaseURLInvalid, "base URL is not a valid URL")
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", publicErr(reasonBaseURLInvalid, "base URL must be an absolute http(s) URL")
	}
	if parsed.User != nil {
		return "", publicErr(reasonBaseURLInvalid, "base URL must not contain user info")
	}
	if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return "", publicErr(reasonBaseURLInvalid, "base URL must not contain a query or fragment")
	}

	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", publicErr(reasonBaseURLInvalid, "base URL must use http or https")
	}
	host := strings.ToLower(parsed.Host)
	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return "", publicErr(reasonBaseURLInvalid, "base URL must include a host")
	}
	if scheme == "http" && !isLoopbackHost(hostname) {
		return "", publicErr(reasonBaseURLInsecure, "base URL must use https unless it points at loopback")
	}

	path := strings.TrimRight(parsed.EscapedPath(), "/")
	// 常见误粘贴：把授权端点当成 base URL。剥掉后仍指向站点根。
	if strings.HasSuffix(strings.ToLower(path), "/api/oauth") {
		path = path[:len(path)-len("/api/oauth")]
	}
	path = strings.TrimRight(path, "/")
	if path != "" {
		cleaned := pathpkg.Clean(path)
		if cleaned == "." || cleaned == "/" {
			cleaned = ""
		}
		if strings.HasPrefix(cleaned, "..") {
			return "", publicErr(reasonBaseURLInvalid, "base URL must not escape the site root")
		}
		path = cleaned
	}

	return scheme + "://" + host + path, nil
}

// EndpointsFor 把归一化后的 base URL 映射到 OAuth2 端点。
func EndpointsFor(base string) Endpoints {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	return Endpoints{
		Authorize: base + "/api/oauth/authorize",
		Token:     base + "/api/oauth/token",
		Userinfo:  base + "/api/oauth/userinfo",
		Docs:      base + "/api/oauth/docs",
		// SForum 的 public unsafe 路由要求 CSRF 双提交；握手端点会种下 csrf_ cookie。
		CSRF: base + "/api/oauth/csrf",
	}
}

func isLoopbackHost(hostname string) bool {
	hostname = strings.ToLower(strings.TrimSpace(hostname))
	if hostname == "localhost" || strings.HasSuffix(hostname, ".localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}
