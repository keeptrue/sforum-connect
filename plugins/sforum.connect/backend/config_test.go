package main

import "testing"

func TestLoadConfigFromEnv(t *testing.T) {
	t.Setenv(settingBaseURL, "")
	t.Setenv(settingClientID, " sfo_client_env ")
	t.Setenv(settingClientSecret, " sfos_env ")

	cfg := LoadConfigFromEnv()
	if cfg.BaseURL != defaultBaseURL {
		t.Fatalf("base URL = %q, want default", cfg.BaseURL)
	}
	if cfg.ClientID != "sfo_client_env" || cfg.ClientSecret != "sfos_env" {
		t.Fatalf("credentials not trimmed: %q / %q", cfg.ClientID, cfg.ClientSecret)
	}
	if cfg.Endpoints.Token != defaultBaseURL+"/api/oauth/token" {
		t.Fatalf("token endpoint = %q", cfg.Endpoints.Token)
	}
	if err := cfg.Ready(); err != nil {
		t.Fatalf("ready: %v", err)
	}
}

func TestConfigRejectsInvalidBaseURL(t *testing.T) {
	cfg := NewConfig("http://example.com", "id", "secret")
	if cfg.BaseURLErr == nil {
		t.Fatal("expected base URL error")
	}
	if reason := publicReason(cfg.Ready()); reason != reasonBaseURLInsecure {
		t.Fatalf("ready reason = %q", reason)
	}
}

func TestConfigRequiresCredentials(t *testing.T) {
	cfg := NewConfig("https://bbs.dalao.me", "id", "")
	if reason := publicReason(cfg.Ready()); reason != reasonCredentialsMissing {
		t.Fatalf("reason = %q", reason)
	}
	if cfg.CredentialsPresent() {
		t.Fatal("credentials must be incomplete")
	}
}
