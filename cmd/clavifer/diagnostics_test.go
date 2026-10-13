package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Keep synthetic fixtures for review instead of automatically deleting files.
// Inject the config directory so macOS tests also avoid the real login profile.
func fixtureDir() (string, error) {
	root := os.Getenv("CLAVIFER_TEST_ARTIFACTS")
	if root == "" {
		root = filepath.Join("..", "..", "work", "cli-test-artifacts")
	}
	if err := os.MkdirAll(root, 0700); err != nil {
		return "", err
	}
	dir, err := os.MkdirTemp(root, "fixture-")
	if err != nil {
		return "", err
	}
	return filepath.Abs(dir)
}
func testConfig(t *testing.T) string {
	t.Helper()
	dir, err := fixtureDir()
	if err != nil {
		t.Fatal(err)
	}
	previousDir, previousProfile := userConfigDir, selectedProfile
	userConfigDir = func() (string, error) { return dir, nil }
	selectedProfile = "default"
	t.Cleanup(func() { userConfigDir, selectedProfile = previousDir, previousProfile })
	return dir
}

func TestProfilesListMetadataOnly(t *testing.T) {
	dir := testConfig(t)
	oldGet := credentialGet
	credentialGet = func(_, _ string) (string, error) { t.Fatal("profile listing opened credential store"); return "", nil }
	t.Cleanup(func() { credentialGet = oldGet })
	for _, name := range []string{"default", "codex", "claude"} {
		selectedProfile = name
		if err := save(profile{"https://example.com", "private-installation-id"}); err != nil {
			t.Fatal(err)
		}
	}
	selectedProfile = "codex"
	bad := filepath.Join(dir, "clavifer", "profiles", "broken.json")
	if err := os.WriteFile(bad, []byte(`{"access_token":"do-not-echo-token",`), 0600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := cmdProfiles([]string{"list"}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "private-installation-id") || strings.Contains(out.String(), "do-not-echo-token") {
		t.Fatal("profile listing leaked hidden fields")
	}
	var result struct {
		Profiles []profileSummary `json:"profiles"`
	}
	if json.Unmarshal(out.Bytes(), &result) != nil || len(result.Profiles) != 4 || result.Profiles[0].Status != "invalid" || result.Profiles[2].Name != "codex" || !result.Profiles[2].Selected {
		t.Fatal("profile listing did not distinguish selection and damaged metadata")
	}
}

func TestDoctorOnlineIsRedactedAndMetadataOnly(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "do-not-echo-access", RefreshToken: "do-not-echo-refresh", ExpiresAt: time.Now().Unix() + 600})
	var checks atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		checks.Add(1)
		w.Header().Set("content-type", "application/json")
		switch r.URL.Path {
		case "/healthz":
			if r.Header.Get("authorization") != "" {
				t.Error("health check sent credentials")
			}
			fmt.Fprint(w, `{"ok":true,"service":"clavifer","version":"0.3.0"}`)
		case "/v1/secrets":
			if r.Method != "GET" || r.Header.Get("authorization") != "Bearer do-not-echo-access" {
				t.Error("incorrect metadata request")
			}
			fmt.Fprint(w, `{"items":[{"name":"do-not-echo-resource","id":"hidden-id"}],"connections":[]}`)
		case "/v1/mcp":
			var msg struct {
				Method string `json:"method"`
			}
			if json.NewDecoder(r.Body).Decode(&msg) != nil {
				t.Error("invalid MCP request")
			}
			switch msg.Method {
			case "initialize":
				fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"clavifer"}}}`)
			case "tools/list":
				tools := []map[string]any{}
				for _, name := range expectedTools {
					tools = append(tools, map[string]any{"name": name, "inputSchema": map[string]string{"type": "object"}, "annotations": map[string]bool{"readOnlyHint": name == "credentials.list" || name == "access.status"}})
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 2, "result": map[string]any{"tools": tools}})
			default:
				t.Errorf("doctor invoked forbidden MCP operation: %s", msg.Method)
				w.WriteHeader(400)
			}
		default:
			t.Errorf("doctor used forbidden endpoint: %s", r.URL.Path)
			w.WriteHeader(400)
		}
	}))
	defer s.Close()
	if err := save(profile{s.URL, "hidden-client"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := cmdDoctor(context.Background(), nil, &out); err != nil {
		t.Fatal(err)
	}
	for _, hidden := range []string{"do-not-echo", "hidden-id", "hidden-client"} {
		if strings.Contains(out.String(), hidden) {
			t.Fatal("diagnostic output leaked a credential or resource identifier")
		}
	}
	var report diagnosticReport
	if json.Unmarshal(out.Bytes(), &report) != nil || !report.OK || report.Metadata == nil || report.Metadata.Secrets != 1 || report.Metadata.Connections != 0 || len(report.Tools) != 4 || checks.Load() != 4 {
		t.Fatal("diagnostic checks did not validate service, authorization and tools")
	}
}

func TestDoctorOfflineDoesNotRefresh(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "old", RefreshToken: "refresh", ExpiresAt: 1})
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer s.Close()
	if err := save(profile{s.URL, "offline"}); err != nil {
		t.Fatal(err)
	}
	report := diagnose(context.Background(), true)
	if !report.OK || !report.Offline || calls.Load() != 0 || report.Checks[1].Status != "warn" {
		t.Fatal("offline diagnostic contacted network or treated refresh availability as verified login")
	}
}

func TestDoctorRejectsUntrustedHealthBeforeAuthentication(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "synthetic", ExpiresAt: time.Now().Unix() + 600})
	var authenticated atomic.Bool
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "" {
			authenticated.Store(true)
		}
		fmt.Fprint(w, `{"ok":true,"service":"different-service","version":"0.3.0"}`)
	}))
	defer s.Close()
	if err := save(profile{s.URL, "health"}); err != nil {
		t.Fatal(err)
	}
	report := diagnose(context.Background(), false)
	if report.OK || authenticated.Load() {
		t.Fatal("doctor authenticated to an incompatible health service")
	}
}

func TestDoctorRevokedSessionAndCredentialStoreFailure(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "synthetic", ExpiresAt: time.Now().Unix() + 600})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			fmt.Fprint(w, `{"ok":true,"service":"clavifer","version":"0.3.0"}`)
			return
		}
		w.WriteHeader(401)
		fmt.Fprint(w, `{"error":"do-not-echo-server-error"}`)
	}))
	defer s.Close()
	if err := save(profile{s.URL, "revoked"}); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if cmdDoctor(context.Background(), nil, &out) == nil || strings.Contains(out.String(), "do-not-echo") || !strings.Contains(out.String(), "revoked") {
		t.Fatal("revocation was not safely diagnosed")
	}
	credentialGet = func(_, _ string) (string, error) { return "", errors.New("do-not-echo-keyring-error") }
	out.Reset()
	if cmdDoctor(context.Background(), []string{"--offline"}, &out) == nil || strings.Contains(out.String(), "do-not-echo") || !strings.Contains(out.String(), "system credential store") {
		t.Fatal("credential store failure was not safely diagnosed")
	}
}

func TestRunSharedSecretChild(t *testing.T) {
	if os.Getenv("CLAVIFER_SHARED_TEST_CHILD") != "1" {
		return
	}
	if os.Getenv("TEST_TOKEN") != "first-token" || os.Getenv("TEST_USERNAME") != "first-user" {
		os.Exit(9)
	}
	os.Exit(0)
}

func TestRunValidatesBeforeReadsAndReusesSecretSnapshot(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "synthetic", ExpiresAt: time.Now().Unix() + 600})
	t.Setenv("CLAVIFER_SHARED_TEST_CHILD", "1")
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 1 {
			fmt.Fprint(w, `{"values":{"token":"second-token","username":"second-user"}}`)
			return
		}
		fmt.Fprint(w, `{"values":{"token":"first-token","username":"first-user"}}`)
	}))
	defer s.Close()
	if err := save(profile{s.URL, "run-snapshot"}); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"BAD-NAME=id.token", "TEST_TOKEN=id.token", "MALFORMED"} {
		if err := cmdRun(context.Background(), []string{"--bind", "TEST_TOKEN=id.token", "--bind", bad, "--", "unused"}); err == nil || calls.Load() != 0 {
			t.Fatal("invalid binding triggered a secret read")
		}
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmdRun(context.Background(), []string{"--bind", "TEST_TOKEN=id.token", "--bind", "TEST_USERNAME=id.username", "--", binary, "-test.run=^TestRunSharedSecretChild$"}); err != nil {
		var child *exec.ExitError
		if errors.As(err, &child) {
			t.Fatal("the child did not receive fields from the same secret version")
		}
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatal("same secret was fetched more than once")
	}
}

func TestCommandArgumentsRejectedBeforeEffects(t *testing.T) {
	testConfig(t)
	for _, args := range [][]string{{"list", "extra"}, {"mcp", "extra"}, {"version", "extra"}, {"login", "extra"}, {"request", "extra"}, {"doctor", "extra"}, {"profiles"}, {"profiles", "remove"}} {
		if err := execute(context.Background(), args); err == nil {
			t.Errorf("accepted extra or unsupported arguments: %v", args)
		}
	}
}

func TestOversizedProfileRejected(t *testing.T) {
	testConfig(t)
	path, err := configPath()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte(strings.Repeat("x", 16385)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = load(); err == nil || strings.Contains(err.Error(), "xxx") {
		t.Fatal("unbounded or unredacted profile parsing")
	}
}

func TestArchiveNeverReplacesAnExistingFile(t *testing.T) {
	dir := testConfig(t)
	source, destination := filepath.Join(dir, "source.json"), filepath.Join(dir, "existing-archive.json")
	if err := os.WriteFile(source, []byte("source-metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("existing-metadata"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := renameWithoutReplace(source, destination); !errors.Is(err, os.ErrExist) {
		t.Fatalf("expected destination-exists error, got %v", err)
	}
	for path, expected := range map[string]string{source: "source-metadata", destination: "existing-metadata"} {
		contents, err := os.ReadFile(path)
		if err != nil || string(contents) != expected {
			t.Fatal("archive operation replaced or lost a file")
		}
	}
}
