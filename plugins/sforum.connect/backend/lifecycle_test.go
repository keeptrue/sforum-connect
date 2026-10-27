package main

import (
	"context"
	"strings"
	"testing"

	protocolwire "github.com/keeptrue/sforum/apps/api/sdk/plugin/v2/gen/sforum/protocol/v2"
)

func lifecycleRequest(action protocolwire.LifecycleAction) *protocolwire.LifecycleRequest {
	return &protocolwire.LifecycleRequest{
		Context: &protocolwire.RequestContext{
			Extension: &protocolwire.ExtensionIdentity{ExtensionId: extID},
		},
		Action:      action,
		PlanVersion: lifecycleContract,
		StepId:      "step-1",
	}
}

func TestLifecycleRejectsInvalidRequests(t *testing.T) {
	cases := []struct {
		name    string
		request *protocolwire.LifecycleRequest
		want    string
	}{
		{"nil request", nil, "invalid lifecycle request"},
		{
			"wrong extension",
			func() *protocolwire.LifecycleRequest {
				req := lifecycleRequest(protocolwire.LifecycleAction_LIFECYCLE_ACTION_INSTALL)
				req.Context.Extension.ExtensionId = "other.extension"
				return req
			}(),
			"invalid lifecycle request",
		},
		{
			"wrong contract",
			func() *protocolwire.LifecycleRequest {
				req := lifecycleRequest(protocolwire.LifecycleAction_LIFECYCLE_ACTION_INSTALL)
				req.PlanVersion = "other.contract@1"
				return req
			}(),
			"invalid lifecycle request",
		},
		{
			"missing step",
			func() *protocolwire.LifecycleRequest {
				req := lifecycleRequest(protocolwire.LifecycleAction_LIFECYCLE_ACTION_INSTALL)
				req.StepId = ""
				return req
			}(),
			"invalid lifecycle request",
		},
		{
			"unsupported action",
			lifecycleRequest(protocolwire.LifecycleAction_LIFECYCLE_ACTION_UNSPECIFIED),
			"unsupported lifecycle action",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := handleLifecycle(context.Background(), tc.request, nil)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestLifecycleAcceptsSupportedActions(t *testing.T) {
	// progress 为 nil 时 Send 会返回 "plugin progress stream is nil"：
	// 走到这里即证明请求已通过校验与动作白名单。
	for _, action := range []protocolwire.LifecycleAction{
		protocolwire.LifecycleAction_LIFECYCLE_ACTION_INSTALL,
		protocolwire.LifecycleAction_LIFECYCLE_ACTION_ENABLE,
		protocolwire.LifecycleAction_LIFECYCLE_ACTION_DISABLE,
		protocolwire.LifecycleAction_LIFECYCLE_ACTION_ROLLBACK,
		protocolwire.LifecycleAction_LIFECYCLE_ACTION_UNINSTALL,
	} {
		err := handleLifecycle(context.Background(), lifecycleRequest(action), nil)
		if err == nil || !strings.Contains(err.Error(), "progress stream is nil") {
			t.Fatalf("action %v error = %v", action, err)
		}
	}
}

func TestLifecycleHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := handleLifecycle(ctx, lifecycleRequest(protocolwire.LifecycleAction_LIFECYCLE_ACTION_INSTALL), nil)
	if err == nil {
		t.Fatal("cancelled context must fail")
	}
}
