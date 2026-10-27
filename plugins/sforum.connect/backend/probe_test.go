package main

import (
	"context"
	"net/http"
	"testing"
)

func TestProbeOKWithDocs(t *testing.T) {
	fake := newFakeProvider(t)
	oauth := NewSForumOAuth(fake.config(), nil)

	result := oauth.Probe(context.Background())
	if !result.OK || result.Reason != reasonProbeOK {
		t.Fatalf("probe = %+v", result)
	}
}

func TestProbeFallsBackToAuthorizeShape(t *testing.T) {
	fake := newFakeProvider(t)
	fake.DocsStatus = http.StatusNotFound
	fake.DocsBody = "not found"
	oauth := NewSForumOAuth(fake.config(), nil)

	result := oauth.Probe(context.Background())
	if !result.OK || result.Reason != reasonProbeOK {
		t.Fatalf("probe = %+v", result)
	}
}

func TestProbeMalformedDocsFallsBack(t *testing.T) {
	fake := newFakeProvider(t)
	fake.DocsStatus = http.StatusOK
	fake.DocsBody = "<html>catch all</html>"
	oauth := NewSForumOAuth(fake.config(), nil)

	result := oauth.Probe(context.Background())
	if !result.OK || result.Reason != reasonProbeOK {
		t.Fatalf("probe = %+v", result)
	}
}

func TestProbeProviderMissing(t *testing.T) {
	fake := newFakeProvider(t)
	fake.DocsStatus = http.StatusNotFound
	fake.DocsBody = "not found"
	fake.AuthorizeStatus = http.StatusNotFound
	oauth := NewSForumOAuth(fake.config(), nil)

	result := oauth.Probe(context.Background())
	if result.OK {
		t.Fatalf("probe must fail: %+v", result)
	}
	if result.Reason != reasonProviderMissing {
		t.Fatalf("reason = %q", result.Reason)
	}
}

func TestProbeUnexpectedAuthorizeStatus(t *testing.T) {
	fake := newFakeProvider(t)
	fake.DocsStatus = http.StatusNotFound
	fake.AuthorizeStatus = http.StatusInternalServerError
	oauth := NewSForumOAuth(fake.config(), nil)

	result := oauth.Probe(context.Background())
	if result.OK || result.Reason != reasonEndpointError {
		t.Fatalf("probe = %+v", result)
	}
}

func TestProbeUnreachable(t *testing.T) {
	// 关闭的 loopback 端口：连接被拒，且不触发非 https 拒绝。
	oauth := NewSForumOAuth(NewConfig("http://127.0.0.1:1", "id", "secret"), nil)
	result := oauth.Probe(context.Background())
	if result.OK || result.Reason != reasonEndpointUnreachable {
		t.Fatalf("probe = %+v", result)
	}
}

func TestProbeRequiresCredentials(t *testing.T) {
	oauth := NewSForumOAuth(NewConfig("https://bbs.dalao.me", "", "secret"), nil)
	if result := oauth.Probe(context.Background()); result.Reason != reasonClientIDMissing {
		t.Fatalf("reason = %q", result.Reason)
	}
	oauth = NewSForumOAuth(NewConfig("https://bbs.dalao.me", "id", ""), nil)
	if result := oauth.Probe(context.Background()); result.Reason != reasonClientSecretMissing {
		t.Fatalf("reason = %q", result.Reason)
	}
}

func TestProbeRejectsInvalidBaseURL(t *testing.T) {
	oauth := NewSForumOAuth(NewConfig("http://example.com", "id", "secret"), nil)
	result := oauth.Probe(context.Background())
	if result.Reason != reasonBaseURLInsecure {
		t.Fatalf("reason = %q", result.Reason)
	}
}

func TestDocsHasEndpoints(t *testing.T) {
	if !docsHasEndpoints([]byte(`{"endpoints":[{"path":"/api/oauth/authorize"},{"path":"/api/oauth/token"},{"path":"/api/oauth/userinfo"}]}`)) {
		t.Fatal("complete docs must pass")
	}
	if docsHasEndpoints([]byte(`{"endpoints":[{"path":"/api/oauth/authorize"}]}`)) {
		t.Fatal("incomplete docs must fail")
	}
	if docsHasEndpoints([]byte(`not json`)) {
		t.Fatal("malformed docs must fail")
	}
}
