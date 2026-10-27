package main

import (
	"context"
	"net/url"
	"strings"
	"testing"

	pluginv2 "github.com/keeptrue/sforum/apps/api/sdk/plugin/v2"
	protocolwire "github.com/keeptrue/sforum/apps/api/sdk/plugin/v2/gen/sforum/protocol/v2"
)

func newIdentityCall(t *testing.T, operation string, input map[string]any) *pluginv2.IdentityProviderCall {
	t.Helper()
	document, err := pluginv2.NewTypedDocument(schemaID("start.input@1"), input)
	if err != nil {
		t.Fatalf("typed document: %v", err)
	}
	return &pluginv2.IdentityProviderCall{
		Context:         &protocolwire.RequestContext{},
		ID:              authProviderID,
		ContractVersion: authProviderID + "@1",
		Kind:            "auth",
		Handler:         handlerName,
		Operation:       operation,
		Input:           document,
	}
}

func TestRegistryRegistersAllOperations(t *testing.T) {
	registry, err := newIdentityRegistry(NewSForumOAuth(NewConfig("https://bbs.dalao.me", "id", "secret"), nil))
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	definitions := registry.Definitions()
	if len(definitions) != 1 {
		t.Fatalf("definitions = %d", len(definitions))
	}
	if definitions[0].ID != authProviderID || definitions[0].Handler != handlerName {
		t.Fatalf("definition = %+v", definitions[0])
	}
	if len(definitions[0].Operations) != 7 {
		t.Fatalf("operations = %d", len(definitions[0].Operations))
	}
}

func TestHandleStartBuildsRedirect(t *testing.T) {
	oauth := NewSForumOAuth(NewConfig("https://bbs.dalao.me", "id", "secret"), nil)
	call := newIdentityCall(t, "login.start", map[string]any{
		"correlationId": "corr-1",
		"state":         "state-1",
		"codeChallenge": "challenge-1",
		"callbackUrl":   testCallback,
	})

	output, err := handleAuthOperation(context.Background(), oauth, call)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	values := pluginv2.TypedDocumentValues(output)
	if values["status"] != "redirect" {
		t.Fatalf("status = %v", values["status"])
	}
	redirect, _ := values["redirectUrl"].(string)
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("redirect URL: %v", err)
	}
	if parsed.Host != "bbs.dalao.me" || parsed.Path != "/api/oauth/authorize" {
		t.Fatalf("redirect = %s", redirect)
	}
	if parsed.Query().Get("state") != "state-1" {
		t.Fatalf("state lost: %s", redirect)
	}
}

func TestHandleStartRejectsNonS256(t *testing.T) {
	oauth := NewSForumOAuth(NewConfig("https://bbs.dalao.me", "id", "secret"), nil)
	call := newIdentityCall(t, "login.start", map[string]any{
		"correlationId":       "corr-1",
		"state":               "state-1",
		"codeChallenge":       "challenge-1",
		"codeChallengeMethod": "plain",
		"callbackUrl":         testCallback,
	})

	_, err := handleAuthOperation(context.Background(), oauth, call)
	if reason := publicReason(err); reason != reasonPKCEMethodUnsupported {
		t.Fatalf("reason = %q", reason)
	}
}

func TestHandleStartRequiresCorrelation(t *testing.T) {
	oauth := NewSForumOAuth(NewConfig("https://bbs.dalao.me", "id", "secret"), nil)
	call := newIdentityCall(t, "login.start", map[string]any{
		"state":         "state-1",
		"codeChallenge": "challenge-1",
		"callbackUrl":   testCallback,
	})
	_, err := handleAuthOperation(context.Background(), oauth, call)
	if reason := publicReason(err); reason != reasonStartInputInvalid {
		t.Fatalf("reason = %q", reason)
	}
}

func TestHandleCompleteRequiresFields(t *testing.T) {
	oauth := NewSForumOAuth(NewConfig("https://bbs.dalao.me", "id", "secret"), nil)
	call := newIdentityCall(t, "login.complete", map[string]any{
		"correlationId": "corr-1",
	})
	_, err := handleAuthOperation(context.Background(), oauth, call)
	if reason := publicReason(err); reason != reasonCompleteInputInvalid {
		t.Fatalf("reason = %q", reason)
	}
}

func TestHandleCompleteEndToEnd(t *testing.T) {
	fake := newFakeProvider(t)
	oauth := NewSForumOAuth(fake.config(), nil)
	verifier := "verifier-abcdefghijklmnopqrstuvwxyz-0123456789"
	code := fake.IssueCode(s256(verifier))
	call := newIdentityCall(t, "registration.complete", map[string]any{
		"correlationId":   "corr-1",
		"completionToken": code,
		"codeVerifier":    verifier,
		"callbackUrl":     fake.RedirectURI,
	})

	output, err := handleAuthOperation(context.Background(), oauth, call)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	values := pluginv2.TypedDocumentValues(output)
	if values["providerSubject"] != "42" {
		t.Fatalf("subject = %v", values["providerSubject"])
	}
	if values["emailHint"] != "alice@example.com" || values["emailVerified"] != true {
		t.Fatalf("email = %v / %v", values["emailHint"], values["emailVerified"])
	}
	if _, present := values["providerSubjectDigest"]; present {
		t.Fatal("the plugin must never emit a subject digest")
	}
}

func TestHandleRejectsHandlerDrift(t *testing.T) {
	oauth := NewSForumOAuth(NewConfig("https://bbs.dalao.me", "id", "secret"), nil)
	call := newIdentityCall(t, "login.start", map[string]any{
		"correlationId": "corr-1",
		"state":         "state-1",
		"codeChallenge": "challenge-1",
		"callbackUrl":   testCallback,
	})
	call.Handler = "sforum.connect.other"

	_, err := handleAuthOperation(context.Background(), oauth, call)
	if err == nil || !strings.Contains(err.Error(), "handler drifted") {
		t.Fatalf("error = %v", err)
	}
}

func TestHandleRejectsAuthorityProjection(t *testing.T) {
	oauth := NewSForumOAuth(NewConfig("https://bbs.dalao.me", "id", "secret"), nil)
	call := newIdentityCall(t, "login.start", map[string]any{
		"correlationId": "corr-1",
		"state":         "state-1",
		"codeChallenge": "challenge-1",
		"callbackUrl":   testCallback,
	})
	call.Context.GrantedAuthority = []*protocolwire.AuthorityGrant{{}}

	_, err := handleAuthOperation(context.Background(), oauth, call)
	if err == nil || !strings.Contains(err.Error(), "authority projection") {
		t.Fatalf("error = %v", err)
	}
}

func TestHandleUnknownOperation(t *testing.T) {
	oauth := NewSForumOAuth(NewConfig("https://bbs.dalao.me", "id", "secret"), nil)
	call := newIdentityCall(t, "login.unknown", map[string]any{"correlationId": "corr-1"})
	_, err := handleAuthOperation(context.Background(), oauth, call)
	if err == nil || !strings.Contains(err.Error(), "unknown identity operation") {
		t.Fatalf("error = %v", err)
	}
}

func TestHandleProbe(t *testing.T) {
	fake := newFakeProvider(t)
	oauth := NewSForumOAuth(fake.config(), nil)
	call := newIdentityCall(t, "provider.probe", map[string]any{})

	output, err := handleAuthOperation(context.Background(), oauth, call)
	if err != nil {
		t.Fatalf("handle: %v", err)
	}
	values := pluginv2.TypedDocumentValues(output)
	if values["ok"] != true || values["reason"] != reasonProbeOK {
		t.Fatalf("probe output = %v", values)
	}
}
