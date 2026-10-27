package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ProbeResult 是有界配置/可达性探测结果。
// 在没有授权码的情况下无法证明 client_secret 正确；不得声称「密钥已验证」。
type ProbeResult struct {
	OK      bool
	Reason  string
	Message string
}

// probeTimeout 短于 Manifest 的 3000ms 操作预算，避免管理端等待到超时。
const probeTimeout = 2500 * time.Millisecond

// Probe 检查配置是否齐全，并用站点自己的 /api/oauth/docs 证明这是
// 一个装了 OAuth2 Provider 的 SForum 站点；旧版本没有 docs 时退回到
// 「无参数访问授权端点」的形状探测。
func (o *SForumOAuth) Probe(ctx context.Context) ProbeResult {
	if o == nil {
		return ProbeResult{Reason: reasonConfigMissing, Message: "the SForum OAuth2 client is not configured"}
	}
	if o.Config.BaseURLErr != nil {
		return ProbeResult{
			Reason:  publicReason(o.Config.BaseURLErr),
			Message: publicMessage(o.Config.BaseURLErr),
		}
	}
	if strings.TrimSpace(o.Config.ClientID) == "" {
		return ProbeResult{Reason: reasonClientIDMissing, Message: "Client ID is not configured"}
	}
	if strings.TrimSpace(o.Config.ClientSecret) == "" {
		return ProbeResult{Reason: reasonClientSecretMissing, Message: "Client Secret is not configured"}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	docsStatus, docsBody, docsErr := o.getLimited(probeCtx, o.Config.Endpoints.Docs, maxProbeBytes)
	if docsErr == nil && docsStatus == http.StatusOK && docsHasEndpoints(docsBody) {
		return ProbeResult{
			OK:     true,
			Reason: reasonProbeOK,
			Message: "站点可达，OAuth2 授权、令牌与用户资料端点均已声明。" +
				"client_id/client_secret 是否存在已确认；client_secret 是否正确无法在无授权码时证明。",
		}
	}

	authStatus, _, authErr := o.getLimited(probeCtx, o.Config.Endpoints.Authorize, maxProbeBytes)
	if authErr != nil {
		if docsErr != nil {
			return ProbeResult{
				Reason:  reasonEndpointUnreachable,
				Message: "无法连接站点，请检查 base URL、网络与站点是否在线。",
			}
		}
		return ProbeResult{
			Reason:  reasonEndpointError,
			Message: "站点可达，但授权端点的探测请求失败。",
		}
	}

	switch authStatus {
	case http.StatusBadRequest, http.StatusUnauthorized:
		// 无参数访问授权端点时，Provider 会返回 400 JSON；纯 SForum 站点是 404。
		return ProbeResult{
			OK:     true,
			Reason: reasonProbeOK,
			Message: "站点可达并响应 OAuth2 授权端点（未找到 /api/oauth/docs）。" +
				"client_secret 是否正确无法在无授权码时证明。",
		}
	case http.StatusNotFound:
		return ProbeResult{
			Reason:  reasonProviderMissing,
			Message: "站点可达，但没有检测到 OAuth2 Provider：授权端点返回 404。请先在站点启用 SForum OAuth2 Provider。",
		}
	default:
		return ProbeResult{
			Reason:  reasonEndpointError,
			Message: fmt.Sprintf("授权端点返回了非预期状态 %d。", authStatus),
		}
	}
}

// getLimited 发起一次有界的 GET，返回状态码与响应体。
func (o *SForumOAuth) getLimited(ctx context.Context, endpoint string, limit int64) (int, []byte, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", userAgent)

	response, err := o.HTTPClient.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()

	body, readErr := io.ReadAll(io.LimitReader(response.Body, limit))
	if readErr != nil {
		return response.StatusCode, nil, readErr
	}
	return response.StatusCode, body, nil
}

// docsHasEndpoints 校验 /api/oauth/docs 的响应里声明了三个必要端点。
func docsHasEndpoints(body []byte) bool {
	var payload struct {
		Endpoints []struct {
			Path string `json:"path"`
		} `json:"endpoints"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return false
	}
	required := map[string]bool{
		"/api/oauth/authorize": false,
		"/api/oauth/token":     false,
		"/api/oauth/userinfo":  false,
	}
	for _, endpoint := range payload.Endpoints {
		if _, ok := required[endpoint.Path]; ok {
			required[endpoint.Path] = true
		}
	}
	for _, found := range required {
		if !found {
			return false
		}
	}
	return true
}
