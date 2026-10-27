package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type manifestOperation struct {
	Name          string `json:"name"`
	InputSchema   string `json:"inputSchema"`
	OutputSchema  string `json:"outputSchema"`
	TimeoutMS     int    `json:"timeoutMs"`
	FailurePolicy string `json:"failurePolicy"`
}

type manifestProvider struct {
	ID              string              `json:"id"`
	ContractVersion string              `json:"contractVersion"`
	Kind            string              `json:"kind"`
	Handler         string              `json:"handler"`
	Icon            string              `json:"icon"`
	Operations      []manifestOperation `json:"operations"`
}

type manifestPackageFile struct {
	ID      string `json:"id"`
	Kind    string `json:"kind"`
	Path    string `json:"path"`
	Version string `json:"version"`
	Digest  string `json:"digest"`
}

type manifestDocument struct {
	ManifestVersion int      `json:"manifestVersion"`
	ID              string   `json:"id"`
	Version         string   `json:"version"`
	Type            string   `json:"type"`
	Capabilities    []string `json:"capabilities"`
	Backend         struct {
		Entry  string `json:"entry"`
		Digest string `json:"digest"`
	} `json:"backend"`
	Identity struct {
		ContractVersion string             `json:"contractVersion"`
		Providers       []manifestProvider `json:"providers"`
	} `json:"identity"`
	PackageFiles []manifestPackageFile `json:"packageFiles"`
}

func loadManifest(t *testing.T) manifestDocument {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("..", "sforum.extension.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var manifest manifestDocument
	if err := json.Unmarshal(body, &manifest); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	return manifest
}

func TestManifestIdentityMatchesRegistry(t *testing.T) {
	manifest := loadManifest(t)
	if manifest.ManifestVersion != 3 {
		t.Fatalf("manifestVersion = %d", manifest.ManifestVersion)
	}
	if manifest.ID != extID || manifest.Type != "plugin" {
		t.Fatalf("id/type = %q/%q", manifest.ID, manifest.Type)
	}
	if manifest.Identity.ContractVersion != extID+".identity@1" {
		t.Fatalf("identity contract = %q", manifest.Identity.ContractVersion)
	}
	if len(manifest.Identity.Providers) != 1 {
		t.Fatalf("providers = %d", len(manifest.Identity.Providers))
	}
	provider := manifest.Identity.Providers[0]
	if provider.ID != authProviderID || provider.Handler != handlerName || provider.Kind != "auth" {
		t.Fatalf("provider = %+v", provider)
	}
	refsByPath := map[string]string{}
	for _, file := range manifest.PackageFiles {
		if file.Kind == "schema" {
			refsByPath[file.Path] = file.ID + "@" + file.Version
		}
	}

	registry, err := newIdentityRegistry(NewSForumOAuth(NewConfig("https://bbs.dalao.me", "id", "secret"), nil))
	if err != nil {
		t.Fatalf("registry: %v", err)
	}
	definitions := registry.Definitions()
	if len(definitions) != 1 {
		t.Fatalf("definitions = %d", len(definitions))
	}
	registered := definitions[0]
	if registered.ID != provider.ID || registered.Handler != provider.Handler ||
		registered.ContractVersion != provider.ContractVersion || registered.Kind != provider.Kind {
		t.Fatalf("registered = %+v", registered)
	}

	byName := map[string]manifestOperation{}
	for _, operation := range provider.Operations {
		byName[operation.Name] = operation
	}
	if len(byName) != len(provider.Operations) {
		t.Fatal("duplicate operation name in manifest")
	}
	if len(registered.Operations) != len(provider.Operations) {
		t.Fatalf("registered %d operations, manifest %d", len(registered.Operations), len(provider.Operations))
	}
	for _, operation := range registered.Operations {
		declared, ok := byName[operation.Name]
		if !ok {
			t.Fatalf("operation %q is registered but not declared", operation.Name)
		}
		if want := refsByPath[declared.InputSchema]; operation.InputSchema != want {
			t.Fatalf("%s input schema = %q, want %q", operation.Name, operation.InputSchema, want)
		}
		if want := refsByPath[declared.OutputSchema]; operation.OutputSchema != want {
			t.Fatalf("%s output schema = %q, want %q", operation.Name, operation.OutputSchema, want)
		}
		if operation.TimeoutMS != declared.TimeoutMS {
			t.Fatalf("%s timeout = %d, manifest %d", operation.Name, operation.TimeoutMS, declared.TimeoutMS)
		}
		if operation.FailurePolicy != "fail_closed" || declared.FailurePolicy != "fail_closed" {
			t.Fatalf("%s failure policy = %q/%q", operation.Name, operation.FailurePolicy, declared.FailurePolicy)
		}
	}
}

func TestManifestSchemaFilesExist(t *testing.T) {
	manifest := loadManifest(t)
	refsByPath := map[string]string{}
	executables := 0
	for _, file := range manifest.PackageFiles {
		if file.Kind == "executable" {
			executables++
			if file.Path != manifest.Backend.Entry {
				t.Fatalf("executable path %q != backend entry %q", file.Path, manifest.Backend.Entry)
			}
			continue
		}
		if file.Kind != "schema" {
			t.Fatalf("unexpected package file kind %q", file.Kind)
		}
		refsByPath[file.Path] = file.ID + "@" + file.Version
		body, err := os.ReadFile(filepath.Join("..", file.Path))
		if err != nil {
			t.Fatalf("read schema %q: %v", file.Path, err)
		}
		var parsed map[string]any
		if err := json.Unmarshal(body, &parsed); err != nil {
			t.Fatalf("schema %q is not JSON: %v", file.Path, err)
		}
	}
	if executables != 1 {
		t.Fatalf("executable declarations = %d", executables)
	}

	provider := manifest.Identity.Providers[0]
	for _, operation := range provider.Operations {
		for _, path := range []string{operation.InputSchema, operation.OutputSchema} {
			ref, ok := refsByPath[path]
			if !ok {
				t.Fatalf("%s references undeclared schema %q", operation.Name, path)
			}
			if !strings.HasPrefix(ref, extID+".schema.") {
				t.Fatalf("schema ref %q is outside the package namespace", ref)
			}
		}
	}
}

func TestManifestCapabilities(t *testing.T) {
	manifest := loadManifest(t)
	want := map[string]bool{"settings.own": false, "net.outbound": false}
	for _, capability := range manifest.Capabilities {
		if _, ok := want[capability]; ok {
			want[capability] = true
		}
	}
	for capability, present := range want {
		if !present {
			t.Fatalf("capability %q is not declared", capability)
		}
	}
}

func TestSettingsDocumentShape(t *testing.T) {
	body, err := os.ReadFile(filepath.Join("..", "manifest", "settings.json"))
	if err != nil {
		t.Fatalf("read settings: %v", err)
	}
	var document struct {
		SchemaVersion int `json:"schemaVersion"`
		UI            struct {
			Mode   string `json:"mode"`
			Layout string `json:"layout"`
			Tabs   []struct {
				ID     string   `json:"id"`
				Groups []string `json:"groups"`
			} `json:"tabs"`
			Groups []struct {
				ID string `json:"id"`
			} `json:"groups"`
			Callouts []struct {
				LinkURL string `json:"linkUrl"`
				Tab     string `json:"tab"`
			} `json:"callouts"`
		} `json:"ui"`
		Fields []struct {
			Key      string `json:"key"`
			Type     string `json:"type"`
			Default  string `json:"default"`
			Required bool   `json:"required"`
			GroupID  string `json:"groupId"`
		} `json:"fields"`
	}
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("parse settings: %v", err)
	}
	if document.SchemaVersion != 1 || document.UI.Mode != "schema" || document.UI.Layout != "tabs" {
		t.Fatalf("unexpected settings shell: %+v", document)
	}

	groupIDs := map[string]bool{}
	for _, group := range document.UI.Groups {
		groupIDs[group.ID] = true
	}
	if !groupIDs["credentials"] {
		t.Fatal("credentials group is missing")
	}
	if len(document.UI.Tabs) != 1 || document.UI.Tabs[0].ID != "connection" {
		t.Fatalf("tabs = %+v", document.UI.Tabs)
	}
	for _, group := range document.UI.Tabs[0].Groups {
		if !groupIDs[group] {
			t.Fatalf("tab references unknown group %q", group)
		}
	}

	byKey := map[string]struct {
		Type     string
		Default  string
		Required bool
		GroupID  string
	}{}
	for _, field := range document.Fields {
		byKey[field.Key] = struct {
			Type     string
			Default  string
			Required bool
			GroupID  string
		}{field.Type, field.Default, field.Required, field.GroupID}
	}
	if len(byKey) != 3 {
		t.Fatalf("fields = %d", len(byKey))
	}
	base, ok := byKey["base_url"]
	if !ok || base.Type != "text" || base.Default != defaultBaseURL || !base.Required {
		t.Fatalf("base_url field = %+v", base)
	}
	clientID, ok := byKey["client_id"]
	if !ok || clientID.Type != "text" || !clientID.Required {
		t.Fatalf("client_id field = %+v", clientID)
	}
	secret, ok := byKey["client_secret"]
	if !ok || secret.Type != "secret" || secret.Required {
		t.Fatalf("client_secret field = %+v", secret)
	}
	for key, field := range byKey {
		if field.GroupID != "credentials" {
			t.Fatalf("%s groupId = %q", key, field.GroupID)
		}
	}

	if len(document.UI.Callouts) != 1 {
		t.Fatalf("callouts = %d", len(document.UI.Callouts))
	}
	callout := document.UI.Callouts[0]
	if !strings.HasPrefix(callout.LinkURL, "https://") || callout.Tab != "connection" {
		t.Fatalf("callout = %+v", callout)
	}
}
