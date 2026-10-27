package main

import (
	"errors"
	"strings"
	"testing"
)

func TestNormalizeBaseURL(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"empty falls back to the official site", "", "https://bbs.dalao.me"},
		{"blank falls back to the official site", "   ", "https://bbs.dalao.me"},
		{"plain https", "https://bbs.dalao.me", "https://bbs.dalao.me"},
		{"trailing slash", "https://bbs.dalao.me/", "https://bbs.dalao.me"},
		{"path prefix", "https://example.com/forum", "https://example.com/forum"},
		{"path prefix with trailing slash", "https://example.com/forum/", "https://example.com/forum"},
		{"pasted authorize endpoint", "https://bbs.dalao.me/api/oauth", "https://bbs.dalao.me"},
		{"pasted api oauth with slash", "https://bbs.dalao.me/forum/api/oauth/", "https://bbs.dalao.me/forum"},
		{"loopback http", "http://127.0.0.1:3000", "http://127.0.0.1:3000"},
		{"localhost http", "http://localhost:8080", "http://localhost:8080"},
		{"ipv6 loopback", "http://[::1]:3000", "http://[::1]:3000"},
		{"host is lowercased", "https://Example.COM/Forum", "https://example.com/Forum"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := NormalizeBaseURL(tc.in)
			if err != nil {
				t.Fatalf("NormalizeBaseURL(%q) error: %v", tc.in, err)
			}
			if got != tc.want {
				t.Fatalf("NormalizeBaseURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestNormalizeBaseURLRejects(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		reason string
	}{
		{"missing scheme", "bbs.dalao.me", reasonBaseURLInvalid},
		{"unsupported scheme", "ftp://bbs.dalao.me", reasonBaseURLInvalid},
		{"userinfo", "https://user:pass@bbs.dalao.me", reasonBaseURLInvalid},
		{"query", "https://bbs.dalao.me/?a=1", reasonBaseURLInvalid},
		{"fragment", "https://bbs.dalao.me/#top", reasonBaseURLInvalid},
		{"plain http", "http://bbs.dalao.me", reasonBaseURLInsecure},
		{"plain http public ip", "http://8.8.8.8", reasonBaseURLInsecure},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NormalizeBaseURL(tc.in)
			if err == nil {
				t.Fatalf("NormalizeBaseURL(%q) accepted", tc.in)
			}
			if reason := publicReason(err); reason != tc.reason {
				t.Fatalf("reason = %q, want %q", reason, tc.reason)
			}
		})
	}
}

func TestEndpointsFor(t *testing.T) {
	endpoints := EndpointsFor("https://bbs.dalao.me/")
	if endpoints.Authorize != "https://bbs.dalao.me/api/oauth/authorize" {
		t.Fatalf("authorize = %q", endpoints.Authorize)
	}
	if endpoints.Token != "https://bbs.dalao.me/api/oauth/token" {
		t.Fatalf("token = %q", endpoints.Token)
	}
	if endpoints.Userinfo != "https://bbs.dalao.me/api/oauth/userinfo" {
		t.Fatalf("userinfo = %q", endpoints.Userinfo)
	}
	if endpoints.Docs != "https://bbs.dalao.me/api/oauth/docs" {
		t.Fatalf("docs = %q", endpoints.Docs)
	}
}

func TestBaseURLPrefixEndpoints(t *testing.T) {
	base, err := NormalizeBaseURL("https://example.com/forum/")
	if err != nil {
		t.Fatalf("normalize: %v", err)
	}
	endpoints := EndpointsFor(base)
	if endpoints.Token != "https://example.com/forum/api/oauth/token" {
		t.Fatalf("token = %q", endpoints.Token)
	}
}

func TestPublicReasonDefaultsToInternal(t *testing.T) {
	if reason := publicReason(errors.New("boom")); reason != reasonInternal {
		t.Fatalf("reason = %q", reason)
	}
	if reason := publicReason(nil); reason != reasonInternal {
		t.Fatalf("nil reason = %q", reason)
	}
}

func TestRedactSensitive(t *testing.T) {
	input := "client_secret=sfos_abc123 access_token=sfoa_token code_verifier=verifier-value Bearer abcdefghijklmnop"
	output := RedactSensitive(input)
	for _, needle := range []string{"sfos_abc123", "sfoa_token", "verifier-value", "abcdefghijklmnop"} {
		if strings.Contains(output, needle) {
			t.Fatalf("redaction left %q in %q", needle, output)
		}
	}
}
