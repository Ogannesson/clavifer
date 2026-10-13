package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/zalando/go-keyring"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Only compiled into the Go test binary. Uses isolated, synthetic E2E credentials
// supplied by the parent test process, never the user's operating-system store.
func TestMCPHostHelper(t *testing.T) {
	if os.Getenv("CLAVIFER_E2E_PROFILE") == "" {
		t.Skip("E2E helper")
	}
	var p profile
	var tok tokenResponse
	if json.Unmarshal([]byte(os.Getenv("CLAVIFER_E2E_PROFILE")), &p) != nil || json.Unmarshal([]byte(os.Getenv("CLAVIFER_E2E_TOKEN")), &tok) != nil {
		os.Exit(2)
	}
	fakeStore(t, tok)
	if bridge(context.Background(), p, os.Stdin, os.Stdout) != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

// The E2E test runs the bridge's waitCommand exactly as written, and under test
// that command names this binary. Given clavifer arguments and the isolated E2E
// login, the binary acts as clavifer instead of running tests.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "--profile" && os.Getenv("CLAVIFER_E2E_PROFILE") != "" {
		var p profile
		var tok tokenResponse
		dir, e := fixtureDir()
		if e != nil || json.Unmarshal([]byte(os.Getenv("CLAVIFER_E2E_PROFILE")), &p) != nil || json.Unmarshal([]byte(os.Getenv("CLAVIFER_E2E_TOKEN")), &tok) != nil {
			os.Exit(2)
		}
		userConfigDir = func() (string, error) { return dir, nil }
		memoryStore(tok)
		if save(p) != nil {
			os.Exit(2)
		}
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func memoryStore(initial tokenResponse) {
	var mu sync.Mutex
	value, _ := json.Marshal(initial)
	credentialGet = func(_, _ string) (string, error) { mu.Lock(); defer mu.Unlock(); return string(value), nil }
	credentialSet = func(_, _, s string) error { mu.Lock(); defer mu.Unlock(); value = []byte(s); return nil }
	credentialDelete = func(_, _ string) error { mu.Lock(); defer mu.Unlock(); value = nil; return nil }
}
func fakeStore(t *testing.T, initial tokenResponse) {
	t.Helper()
	testConfig(t)
	oldGet, oldSet, oldDelete := credentialGet, credentialSet, credentialDelete
	memoryStore(initial)
	t.Cleanup(func() { credentialGet, credentialSet, credentialDelete = oldGet, oldSet, oldDelete })
}
func TestBindValidation(t *testing.T) {
	for _, input := range []string{"missing-equals", "=id.token", "TOKEN=", "TOKEN=id", "TOKEN=id.-field", "BAD-NAME=id.token", "X=id.token\nBAD=1"} {
		if _, _, _, e := parseBind(input); e == nil {
			t.Errorf("accepted %q", input)
		}
	}
	// Server field names allow hyphens, so a granted field must also be bindable.
	n, s, f, e := parseBind("API_KEY=abc-123.api-token")
	if e != nil || n != "API_KEY" || s != "abc-123" || f != "api-token" {
		t.Fatal("valid binding rejected")
	}
	if _, e = parseFields("token,api-key"); e != nil {
		t.Fatal(e)
	}
	if _, e = parseFields(strings.TrimSuffix(strings.Repeat("token,", 21), ",")); e == nil {
		t.Error("accepted more fields than the service allows")
	}
	for _, input := range []string{"", "token,", "token,-bad", "token bad"} {
		if _, e = parseFields(input); e == nil {
			t.Errorf("accepted fields %q", input)
		}
	}
}
func TestServerValidation(t *testing.T) {
	for _, s := range []string{"http://example.com", "https://user:password@example.com", "https://example.com/path", "https://example.com?x=1", "file:///tmp/x"} {
		if _, e := normalizeServer(s); e == nil {
			t.Errorf("accepted %s", s)
		}
	}
	for _, s := range []string{"https://example.com/", "http://127.0.0.1:8787", "http://[::1]:8787"} {
		if _, e := normalizeServer(s); e != nil {
			t.Error(e)
		}
	}
}
func TestConcurrentRefresh(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "expired-test", RefreshToken: "test-refresh", ExpiresAt: 1})
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		_ = r.ParseForm()
		if r.Form.Get("grant_type") != "refresh_token" || r.Form.Get("refresh_token") != "test-refresh" {
			t.Error("bad refresh request")
		}
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"access_token":"renewed-test","refresh_token":"rotated-test","expires_in":600}`)
	}))
	defer server.Close()
	p := profile{server.URL, "installation-refresh"}
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, e := validToken(context.Background(), p)
			if e != nil || token.AccessToken != "renewed-test" {
				t.Errorf("refresh failed: %v", e)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("got %d refresh calls", calls.Load())
	}
}
func TestCredentialStoreFailure(t *testing.T) {
	fakeStore(t, tokenResponse{})
	credentialSet = func(_, _, _ string) error { return errors.New("unavailable") }
	if storeToken(profile{"https://example.com", "a"}, tokenResponse{AccessToken: "test"}) == nil {
		t.Fatal("silently ignored unavailable credential store")
	}
}
func TestProfileReplacement(t *testing.T) {
	testConfig(t)
	for _, client := range []string{"old-installation", "new-installation"} {
		if e := save(profile{"https://example.com", client}); e != nil {
			t.Fatal(e)
		}
	}
	p, e := load()
	if e != nil || p.ClientID != "new-installation" {
		t.Fatalf("profile switch failed: %v", e)
	}
}
func TestNamedProfiles(t *testing.T) {
	testConfig(t)
	previous := selectedProfile
	t.Cleanup(func() { selectedProfile = previous })
	for _, name := range []string{"codex", "claude"} {
		selectedProfile = name
		if e := save(profile{"https://example.com", name + "-installation"}); e != nil {
			t.Fatal(e)
		}
	}
	selectedProfile = "codex"
	p, e := load()
	if e != nil || p.ClientID != "codex-installation" {
		t.Fatal("named profiles are not independent")
	}
	for _, name := range []string{"../other", "C:\\other", "", "a/b", "a.b"} {
		selectedProfile = name
		if _, e := configPath(); e == nil {
			t.Errorf("accepted profile path %q", name)
		}
	}
}
func TestLocalLogout(t *testing.T) {
	fakeStore(t, tokenResponse{})
	var requests atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1) }))
	defer s.Close()
	if e := save(profile{s.URL, "local-logout"}); e != nil {
		t.Fatal(e)
	}
	if e := cmdLogout(context.Background(), []string{"--local"}); e != nil {
		t.Fatal(e)
	}
	if requests.Load() != 0 {
		t.Fatal("local logout contacted server")
	}
	if _, e := load(); e == nil {
		t.Fatal("profile remained after logout")
	}
	path, _ := configPath()
	archives, err := filepath.Glob(path + ".logged-out-*")
	if err != nil || len(archives) != 1 {
		t.Fatal("logout did not retain exactly one metadata archive")
	}
	archived, err := readProfile(archives[0])
	if err != nil || archived.ClientID != "local-logout" {
		t.Fatal("logout archive did not retain metadata")
	}
	profiles, err := listProfiles()
	if err != nil || len(profiles) != 0 {
		t.Fatal("logout archive was treated as an active profile")
	}
}
func TestLoginRateLimit(t *testing.T) {
	fakeStore(t, tokenResponse{})
	var calls atomic.Int32
	var serverURL string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if r.URL.Path == "/api/auth/device/code" {
			_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "synthetic-device", "user_code": "TESTCODE", "verification_uri": serverURL + "/device", "expires_in": 60, "interval": 5})
			return
		}
		if calls.Add(1) == 1 {
			w.Header().Set("retry-after", "5")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"error":"rate_limited"}`)
			return
		}
		fmt.Fprint(w, `{"access_token":"synthetic-login","refresh_token":"synthetic-refresh","expires_in":600}`)
	}))
	defer s.Close()
	serverURL = s.URL
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	started := time.Now()
	if e := cmdLogin(ctx, []string{"--server", serverURL, "--client-id", "rate-limit-test"}); e != nil {
		t.Fatal(e)
	}
	if calls.Load() != 2 || time.Since(started) < 10*time.Second {
		t.Fatal("device login did not respect polling and Retry-After")
	}
	tok, e := savedToken(profile{serverURL, "rate-limit-test"})
	if e != nil || tok.AccessToken != "synthetic-login" {
		t.Fatal("retried login did not save token")
	}
}

// A keep-alive server drops the idle connection from the device-code request
// just as the first poll goes out on it; the poll must reach the server anyway.
func TestLoginPollSurvivesAClosedIdleConnection(t *testing.T) {
	fakeStore(t, tokenResponse{})
	var polls atomic.Int32
	var serverURL string
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		if r.URL.Path == "/api/auth/device/code" {
			_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "synthetic-device", "user_code": "TESTCODE", "verification_uri": serverURL + "/device", "expires_in": 60, "interval": 5})
			return
		}
		if polls.Add(1) == 1 {
			c, _, e := w.(http.Hijacker).Hijack()
			if e != nil {
				t.Error(e)
				return
			}
			c.Close()
			return
		}
		fmt.Fprint(w, `{"access_token":"synthetic-login","refresh_token":"synthetic-refresh","expires_in":600}`)
	}))
	defer s.Close()
	serverURL = s.URL
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if e := cmdLogin(ctx, []string{"--server", serverURL, "--client-id", "closed-idle-test"}); e != nil {
		t.Fatal(e)
	}
	if polls.Load() != 2 {
		t.Fatalf("got %d polls", polls.Load())
	}
}
func TestNoCredentialRedirect(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "test-only", ExpiresAt: time.Now().Unix() + 600})
	var forwarded atomic.Bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { forwarded.Store(true) }))
	defer other.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL, http.StatusTemporaryRedirect)
	}))
	defer s.Close()
	_, _, e := request(context.Background(), profile{s.URL, "a"}, "GET", "/v1/secrets", nil, true)
	if e == nil || forwarded.Load() {
		t.Fatal("followed authenticated redirect")
	}
}
func TestBridgeProtocolOnly(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "test-only", ExpiresAt: time.Now().Unix() + 600})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("authorization") != "Bearer test-only" {
			t.Error("missing authentication")
		}
		var m map[string]any
		_ = json.NewDecoder(r.Body).Decode(&m)
		if m["id"] == nil {
			w.WriteHeader(202)
			return
		}
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[]}}`)
	}))
	defer s.Close()
	var out bytes.Buffer
	e := bridge(context.Background(), profile{s.URL, "a"}, strings.NewReader("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n"), &out)
	if e != nil {
		t.Fatal(e)
	}
	if !json.Valid(bytes.TrimSpace(out.Bytes())) || strings.Contains(out.String(), "test-only") {
		t.Fatal("stdio was polluted or leaked token")
	}
}
func TestRunChild(t *testing.T) {
	if os.Getenv("CLAVIFER_TEST_CHILD") == "1" {
		if os.Getenv("TEST_UPSTREAM_KEY") != "synthetic-secret" {
			os.Exit(9)
		}
		os.Exit(7)
	}
}
func TestRunInjectionAndExit(t *testing.T) {
	t.Setenv("CLAVIFER_TEST_CHILD", "1")
	t.Setenv("TEST_UPSTREAM_KEY", "stale")
	fakeStore(t, tokenResponse{AccessToken: "test-only", ExpiresAt: time.Now().Unix() + 600})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Fields []string `json:"fields"`
		}
		if json.NewDecoder(r.Body).Decode(&body) != nil || len(body.Fields) != 1 || body.Fields[0] != "token" {
			t.Errorf("read did not request only the bound field: %v", body.Fields)
		}
		fmt.Fprint(w, `{"values":{"token":"synthetic-secret"}}`)
	}))
	defer s.Close()
	if e := save(profile{s.URL, "child"}); e != nil {
		t.Fatal(e)
	}
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	err := cmdRun(context.Background(), []string{"--bind", "TEST_UPSTREAM_KEY=id.token", "--", binary, "-test.run=^TestRunChild$"})
	var child *exec.ExitError
	if !errors.As(err, &child) || child.ExitCode() != 7 {
		t.Fatalf("child exit not preserved: %v", err)
	}
	path, _ := configPath()
	b, _ := os.ReadFile(filepath.Clean(path))
	if strings.Contains(string(b), "test-only") || strings.Contains(string(b), "synthetic-secret") {
		t.Fatal("credential persisted in profile")
	}
}

func TestRunInterruptChild(t *testing.T) {
	if os.Getenv("CLAVIFER_TEST_INTERRUPT_CHILD") != "1" {
		return
	}
	// Notifying makes the process survive the interrupt so the parent can be
	// observed granting it time to finish instead of terminating it.
	signal.Notify(make(chan os.Signal, 1), os.Interrupt)
	time.Sleep(800 * time.Millisecond)
	os.Exit(4)
}
func TestRunInterruptLetsChildFinish(t *testing.T) {
	t.Setenv("CLAVIFER_TEST_INTERRUPT_CHILD", "1")
	fakeStore(t, tokenResponse{AccessToken: "test-only", ExpiresAt: time.Now().Unix() + 600})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"values":{"token":"synthetic-secret"}}`) }))
	defer s.Close()
	if e := save(profile{s.URL, "interrupt"}); e != nil {
		t.Fatal(e)
	}
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := cmdRun(ctx, []string{"--bind", "TEST_UPSTREAM_KEY=id.token", "--", binary, "-test.run=^TestRunInterruptChild$"})
	var child *exec.ExitError
	if !errors.As(err, &child) || child.ExitCode() != 4 {
		t.Fatalf("interrupted child was not allowed to exit on its own: %v", err)
	}
	if time.Since(started) < 700*time.Millisecond {
		t.Fatal("interrupt terminated the child instead of letting it clean up")
	}
}
func TestTransportFailureWording(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "test-only", ExpiresAt: time.Now().Unix() + 600})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	unreachable := profile{s.URL, "offline"}
	s.Close()
	for path, expected := range map[string]string{"/v1/secrets/id/read": "service unavailable", "/v1/access-requests": "unknown outcome", "/v1/mcp": "unknown outcome"} {
		_, _, e := request(context.Background(), unreachable, "POST", path, nil, true)
		if e == nil || !strings.Contains(e.Error(), expected) {
			t.Errorf("%s reported %v", path, e)
		}
	}
}
func TestRefreshThatCannotBeSavedStopsTheCommand(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "expired-test", RefreshToken: "test-refresh", ExpiresAt: 1})
	credentialSet = func(_, _, _ string) error { return errors.New("store locked") }
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"access_token":"renewed-test","refresh_token":"rotated-test","expires_in":600}`)
	}))
	defer s.Close()
	token, e := validToken(context.Background(), profile{s.URL, "unsaveable"})
	if e == nil || !strings.Contains(e.Error(), "run login again") || token.AccessToken != "" {
		t.Fatalf("an unsaved rotation was treated as usable: %v", e)
	}
}
func TestSavedTokenSeparatesMissingLoginFromBrokenStore(t *testing.T) {
	fakeStore(t, tokenResponse{})
	credentialGet = func(_, _ string) (string, error) { return "", keyring.ErrNotFound }
	if _, e := savedToken(profile{"https://example.com", "a"}); !errors.Is(e, errNotLoggedIn) {
		t.Fatalf("missing login was not reported as such: %v", e)
	}
	credentialGet = func(_, _ string) (string, error) { return "", errors.New("store locked") }
	_, e := savedToken(profile{"https://example.com", "a"})
	if e == nil || !strings.Contains(e.Error(), "system credential store unavailable") {
		t.Fatalf("store failure was not reported as such: %v", e)
	}
}
func TestBridgeAnswersEveryBatchedRequest(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "test-only", ExpiresAt: time.Now().Unix() + 600})
	var forwarded atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if forwarded.Add(1) == 1 {
			if !bytes.HasPrefix(bytes.TrimSpace(body), []byte("[")) {
				t.Error("batch line was not forwarded unchanged")
			}
			w.WriteHeader(500)
			return
		}
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":3,"result":{}}`)
	}))
	defer s.Close()
	var out bytes.Buffer
	input := "[{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"},{\"jsonrpc\":\"2.0\",\"method\":\"notifications/x\"},{\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}]\n{\"jsonrpc\":\"2.0\",\"id\":3,\"method\":\"tools/list\"}\n"
	if e := bridge(context.Background(), profile{s.URL, "a"}, strings.NewReader(input), &out); e != nil {
		t.Fatal(e)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("batch failure did not keep the bridge running: %q", out.String())
	}
	var failures []struct {
		ID    int `json:"id"`
		Error struct {
			Code int `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(lines[0]), &failures) != nil || len(failures) != 2 || failures[0].ID != 1 || failures[1].ID != 2 || failures[1].Error.Code != -32000 {
		t.Fatalf("batch failure did not answer each request id: %q", lines[0])
	}
}
func TestRequestSecretFields(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "test-only", ExpiresAt: time.Now().Unix() + 600})
	var grants []map[string]any
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Requested struct {
				Grants []map[string]any `json:"grants"`
			} `json:"requested"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		grants = body.Requested.Grants
		fmt.Fprint(w, `{"id":"synthetic-request"}`)
	}))
	defer s.Close()
	if e := save(profile{s.URL, "fields"}); e != nil {
		t.Fatal(e)
	}
	if e := cmdRequest(context.Background(), []string{"--secret", "sid", "--fields", "token,api-key", "--reason", "test"}); e != nil {
		t.Fatal(e)
	}
	fields, _ := grants[0]["fields"].([]any)
	if len(grants) != 1 || len(fields) != 2 || fields[1] != "api-key" {
		t.Fatalf("grant did not carry the requested fields: %v", grants)
	}
	if e := cmdRequest(context.Background(), []string{"--secret", "sid", "--reason", "test"}); e != nil {
		t.Fatal(e)
	}
	if _, present := grants[0]["fields"]; present {
		t.Fatal("omitted --fields must leave the server default of every field")
	}
	if e := cmdRequest(context.Background(), []string{"--connection", "cid", "--fields", "token", "--reason", "test"}); e == nil {
		t.Fatal("accepted --fields for a connection")
	}
}

// Interrupted children, in the three shapes cmdRun has to tell apart: one that
// cleans up and succeeds, and one that ignores the interrupt entirely.
func TestRunGracefulChild(t *testing.T) {
	if os.Getenv("CLAVIFER_TEST_GRACEFUL_CHILD") != "1" {
		return
	}
	signal.Notify(make(chan os.Signal, 1), os.Interrupt)
	time.Sleep(300 * time.Millisecond)
	os.Exit(0)
}
func TestRunStubbornChild(t *testing.T) {
	if os.Getenv("CLAVIFER_TEST_STUBBORN_CHILD") != "1" {
		return
	}
	signal.Notify(make(chan os.Signal, 1), os.Interrupt)
	time.Sleep(30 * time.Second)
	os.Exit(0)
}

// Shared fixture for the interrupt tests: a profile whose secret read always
// succeeds, plus the path of the test binary used as the child.
func interruptFixture(t *testing.T, client string) string {
	t.Helper()
	fakeStore(t, tokenResponse{AccessToken: "test-only", ExpiresAt: time.Now().Unix() + 600})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, `{"values":{"token":"synthetic-secret"}}`) }))
	t.Cleanup(s.Close)
	if e := save(profile{s.URL, client}); e != nil {
		t.Fatal(e)
	}
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	return binary
}
func TestRunReportsAnInterruptedRun(t *testing.T) {
	t.Setenv("CLAVIFER_TEST_GRACEFUL_CHILD", "1")
	binary := interruptFixture(t, "graceful")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	e := cmdRun(ctx, []string{"--bind", "TEST_UPSTREAM_KEY=id.token", "--", binary, "-test.run=^TestRunGracefulChild$"})
	// The shell-visible result of this error is exit 130, set in main.
	if !errors.Is(e, errInterrupted) {
		t.Fatalf("an interrupted run that ended cleanly did not report the interrupt: %v", e)
	}
}
func TestRunKillsAChildThatIgnoresTheInterrupt(t *testing.T) {
	t.Setenv("CLAVIFER_TEST_STUBBORN_CHILD", "1")
	binary := interruptFixture(t, "stubborn")
	previous := childWaitDelay
	childWaitDelay = 300 * time.Millisecond
	t.Cleanup(func() { childWaitDelay = previous })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { time.Sleep(100 * time.Millisecond); cancel() }()
	done := make(chan error, 1)
	go func() {
		done <- cmdRun(ctx, []string{"--bind", "TEST_UPSTREAM_KEY=id.token", "--", binary, "-test.run=^TestRunStubbornChild$"})
	}()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("a killed child was reported as success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the wait delay did not bound how long an unresponsive child may run")
	}
}
func TestBridgeAnswersASingleFailureWithOneObject(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "test-only", ExpiresAt: time.Now().Unix() + 600})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	unreachable := profile{s.URL, "single"}
	s.Close()
	var out bytes.Buffer
	if e := bridge(context.Background(), unreachable, strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}\n"), &out); e != nil {
		t.Fatal(e)
	}
	var failure struct {
		ID int `json:"id"`
	}
	if json.Unmarshal(bytes.TrimSpace(out.Bytes()), &failure) != nil || failure.ID != 1 {
		t.Fatalf("a single request was not answered with a single object: %q", out.String())
	}
}
func TestBridgeSurvivesUnusableLines(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "test-only", ExpiresAt: time.Now().Unix() + 600})
	var forwarded atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		forwarded.Add(1)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":9,"result":{}}`)
	}))
	defer s.Close()
	var out bytes.Buffer
	input := "\n{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\nnot-json\n[1,2]\n{\"jsonrpc\":\"2.0\",\"id\":9,\"method\":\"tools/list\"}\n"
	if e := bridge(context.Background(), profile{s.URL, "a"}, strings.NewReader(input), &out); e != nil {
		t.Fatal(e)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 || forwarded.Load() != 2 {
		t.Fatalf("a malformed line ended the bridge: %d lines, %d forwarded", len(lines), forwarded.Load())
	}
	for _, malformed := range lines[1:3] {
		if !strings.Contains(malformed, "-32700") {
			t.Fatalf("unparseable line was not reported as a parse error: %q", malformed)
		}
	}
	if !strings.Contains(lines[3], `"id":9`) {
		t.Fatalf("the bridge stopped serving after a malformed line: %q", out.String())
	}
}
func TestBridgeDoesNotAnswerAHostResponse(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "test-only", ExpiresAt: time.Now().Unix() + 600})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	unreachable := profile{s.URL, "response"}
	s.Close()
	var out bytes.Buffer
	if e := bridge(context.Background(), unreachable, strings.NewReader("{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{}}\n"), &out); e != nil {
		t.Fatal(e)
	}
	if out.Len() != 0 {
		t.Fatalf("a failed response relay was answered as if it were a request: %q", out.String())
	}
}
func TestSavedTokenReportsDamagedLoginData(t *testing.T) {
	fakeStore(t, tokenResponse{})
	if e := save(profile{"https://example.com", "damaged"}); e != nil {
		t.Fatal(e)
	}
	credentialGet = func(_, _ string) (string, error) { return "{not-json", nil }
	if _, e := savedToken(profile{"https://example.com", "a"}); !errors.Is(e, errUnreadableLogin) {
		t.Fatalf("damaged login data was not separated from a broken store: %v", e)
	}
	report := diagnose(context.Background(), true)
	if report.Checks[1].Status != "fail" || !strings.Contains(report.Checks[1].Detail, "damaged") {
		t.Fatalf("doctor did not advise replacing damaged login data: %v", report.Checks[1])
	}
}

func TestExitCodeMapping(t *testing.T) {
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	child := exec.Command(binary, "-test.run=^TestRunChild$")
	child.Env = append(os.Environ(), "CLAVIFER_TEST_CHILD=1", "TEST_UPSTREAM_KEY=wrong")
	failed := child.Run()
	var exit *exec.ExitError
	if !errors.As(failed, &exit) || exit.ExitCode() != 9 {
		t.Fatalf("test fixture did not produce a child exit status: %v", failed)
	}
	for _, c := range []struct {
		err    error
		code   int
		report bool
	}{
		{errInterrupted, 130, false},
		{fmt.Errorf("wrapped: %w", errInterrupted), 130, false},
		{failed, 9, false},
		{errStillPending, 124, true},
		{errors.New("profile not found"), 1, true},
	} {
		if code, report := exitCode(c.err); code != c.code || report != c.report {
			t.Errorf("exitCode(%v) = %d,%v; want %d,%v", c.err, code, report, c.code, c.report)
		}
	}
}

// A status server that answers each check with the next canned reply, plus a
// short polling interval so waiting tests finish quickly.
func statusFixture(t *testing.T, reply func(call int32, w http.ResponseWriter)) *atomic.Int32 {
	t.Helper()
	fakeStore(t, tokenResponse{AccessToken: "test-only", ExpiresAt: time.Now().Unix() + 600})
	var calls atomic.Int32
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" || r.URL.Path != "/v1/access-requests/req-1" {
			t.Errorf("unexpected status request %s %s", r.Method, r.URL.Path)
		}
		reply(calls.Add(1), w)
	}))
	t.Cleanup(s.Close)
	if e := save(profile{s.URL, "wait"}); e != nil {
		t.Fatal(e)
	}
	previous := statusInterval
	statusInterval = 10 * time.Millisecond
	t.Cleanup(func() { statusInterval = previous })
	return &calls
}
func statusReply(status string) func(int32, http.ResponseWriter) {
	return func(_ int32, w http.ResponseWriter) {
		fmt.Fprintf(w, `{"id":"req-1","status":%q,"expires_at":1}`, status)
	}
}
func TestStatusWaitReturnsTheDecision(t *testing.T) {
	for _, decision := range []string{"approved", "denied", "expired", "executed"} {
		calls := statusFixture(t, func(call int32, w http.ResponseWriter) {
			status := "pending"
			if call >= 3 {
				status = decision
			}
			statusReply(status)(call, w)
		})
		var out bytes.Buffer
		if e := cmdStatus(context.Background(), []string{"req-1"}, &out); e != nil || !strings.Contains(out.String(), `"pending"`) || calls.Load() != 1 {
			t.Fatalf("a plain status check did not report once: %v %q", e, out.String())
		}
		out.Reset()
		// A short timeout turns a missed decision into an immediate failure.
		if e := cmdStatus(context.Background(), []string{"req-1", "--wait", "--timeout", "1s"}, &out); e != nil {
			t.Fatal(e)
		}
		var final struct {
			Status string `json:"status"`
		}
		if json.Unmarshal(out.Bytes(), &final) != nil || final.Status != decision || calls.Load() != 3 {
			t.Fatalf("wait did not end with %s: %q after %d checks", decision, out.String(), calls.Load())
		}
	}
	for _, args := range [][]string{{"req-1", "--timeout", "1m"}, {"-h", "--wait"}, {"_x", "--wait"}} {
		if e := cmdStatus(context.Background(), args, io.Discard); e == nil {
			t.Errorf("accepted status %v", args)
		}
	}
}
func TestStatusWaitTimesOutWhilePending(t *testing.T) {
	statusFixture(t, statusReply("pending"))
	var out bytes.Buffer
	e := cmdStatus(context.Background(), []string{"--wait", "--timeout", "50ms", "req-1"}, &out)
	if !errors.Is(e, errStillPending) || out.Len() != 0 {
		t.Fatalf("a wait that ran out of time was not reported as still pending: %v %q", e, out.String())
	}
	if code, _ := exitCode(e); code != 124 {
		t.Fatalf("timeout exit status %d", code)
	}
}
func TestStatusWaitRespectsRetryAfter(t *testing.T) {
	calls := statusFixture(t, func(call int32, w http.ResponseWriter) {
		if call == 1 {
			w.Header().Set("retry-after", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			fmt.Fprint(w, `{"error":"rate_limited"}`)
			return
		}
		statusReply("denied")(call, w)
	})
	started := time.Now()
	var out bytes.Buffer
	if e := cmdStatus(context.Background(), []string{"req-1", "--wait"}, &out); e != nil || !strings.Contains(out.String(), `"denied"`) {
		t.Fatalf("wait did not continue after a rate limit: %v %q", e, out.String())
	}
	if calls.Load() != 2 || time.Since(started) < time.Second {
		t.Fatalf("wait did not honour Retry-After: %d checks in %v", calls.Load(), time.Since(started))
	}
}
func TestStatusWaitReportsARateLimitBeyondTheTimeout(t *testing.T) {
	statusFixture(t, func(_ int32, w http.ResponseWriter) {
		w.Header().Set("retry-after", "60")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":"rate_limited"}`)
	})
	e := cmdStatus(context.Background(), []string{"req-1", "--wait", "--timeout", "1s"}, io.Discard)
	var ae *apiError
	if errors.Is(e, errStillPending) || !errors.As(e, &ae) || ae.Status != http.StatusTooManyRequests {
		t.Fatalf("a rate limit past the timeout was not reported as a rate limit: %v", e)
	}
}
func TestStatusWaitStopsOnInterrupt(t *testing.T) {
	statusFixture(t, statusReply("pending"))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { time.Sleep(50 * time.Millisecond); cancel() }()
	if e := cmdStatus(ctx, []string{"req-1", "--wait"}, io.Discard); !errors.Is(e, errInterrupted) {
		t.Fatalf("an interrupted wait did not report the interrupt: %v", e)
	}
}

func TestShellWord(t *testing.T) {
	for _, c := range []struct {
		path    string
		windows bool
		want    string
		ok      bool
	}{
		{`C:\Users\user\AppData\Local\clavifer\bin\clavifer.exe`, true, `C:/Users/user/AppData/Local/clavifer/bin/clavifer.exe`, true},
		{`C:\Users\user\My Tools\clavifer.exe`, true, `"C:/Users/user/My Tools/clavifer.exe"`, true},
		{`C:\Users\user\a$b\clavifer.exe`, true, `"C:/Users/user/a$b/clavifer.exe"`, false},
		{"C:\\Users\\user\\a`b\\clavifer.exe", true, "\"C:/Users/user/a`b/clavifer.exe\"", false},
		{`/usr/local/bin/clavifer`, false, `/usr/local/bin/clavifer`, true},
		{`/home/user/a b/it's/$x/clavifer`, false, `'/home/user/a b/it'\''s/$x/clavifer'`, true},
	} {
		if got, ok := shellWord(c.path, c.windows); got != c.want || ok != c.ok {
			t.Errorf("shellWord(%q) = %s,%v; want %s,%v", c.path, got, ok, c.want, c.ok)
		}
	}
}

// Runs a copy of this test binary from a directory with a space through the
// shells an Agent host uses, to show the quoted word survives each of them.
func TestShellWordRunsThroughShells(t *testing.T) {
	binary, e := os.Executable()
	if e != nil {
		t.Fatal(e)
	}
	b, e := os.ReadFile(binary)
	if e != nil {
		t.Fatal(e)
	}
	copied := filepath.Join(t.TempDir(), "with space", "vault ctl"+filepath.Ext(binary))
	if e = os.MkdirAll(filepath.Dir(copied), 0700); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(copied, b, 0700); e != nil {
		t.Fatal(e)
	}
	// Windows PowerShell splits an unquoted -name.value argument at the dot.
	word, _ := shellWord(copied, runtime.GOOS == "windows")
	command := word + " '-test.run=NoSuchTest'"
	shells := [][]string{}
	if runtime.GOOS == "windows" {
		// PowerShell runs a quoted path only through the call operator.
		shells = append(shells, []string{"powershell.exe", "-NoProfile", "-Command", "& " + command})
	}
	if sh, e := exec.LookPath("sh"); e == nil {
		shells = append(shells, []string{sh, "-c", command})
	}
	for _, shell := range shells {
		out, e := exec.Command(shell[0], shell[1:]...).CombinedOutput()
		if e != nil || !strings.Contains(string(out), "PASS") {
			t.Errorf("%s did not run %s: %v %s", shell[0], command, e, out)
		}
	}
}

func TestBridgeAddsWaitCommandToAccessRequestOnly(t *testing.T) {
	fakeStore(t, tokenResponse{AccessToken: "test-only", ExpiresAt: time.Now().Unix() + 600})
	// A served waitCommand is replaced by the bridge's own.
	pending := `{"id":"req-7","status":"pending","approveUrl":"https://example.com/?tab=access","waitCommand":"served-command"}`
	text, _ := json.Marshal(pending)
	replies := map[float64]string{
		1: `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":` + string(text) + `}]}}`,
		2: `{"jsonrpc":"2.0","id":2,"result":{"content":[{"type":"text","text":` + string(text) + `}]}}`,
		3: `{"jsonrpc":"2.0","id":3,"result":{"isError":true,"content":[{"type":"text","text":"{\"error\":\"invalid_arguments\"}"}]}}`,
		4: `not-json`,
	}
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m struct {
			ID float64 `json:"id"`
		}
		_ = json.NewDecoder(r.Body).Decode(&m)
		w.Header().Set("content-type", "application/json")
		fmt.Fprint(w, replies[m.ID])
	}))
	defer s.Close()
	call := func(id int, name string) string {
		return fmt.Sprintf(`{"jsonrpc":"2.0","id":%d,"method":"tools/call","params":{"name":%q,"arguments":{}}}`, id, name)
	}
	input := strings.Join([]string{call(1, "access.request"), call(2, "access.status"), call(3, "access.request"), call(4, "access.request")}, "\n") + "\n"
	var out bytes.Buffer
	if e := bridge(context.Background(), profile{s.URL, "a"}, strings.NewReader(input), &out); e != nil {
		t.Fatal(e)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("got %d lines: %q", len(lines), out.String())
	}
	for i, line := range lines[1:] {
		if line != replies[float64(i+2)] {
			t.Errorf("reply %d was changed: %s", i+2, line)
		}
	}
	var message struct {
		ID     int `json:"id"`
		Result struct {
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"result"`
	}
	var payload map[string]string
	if json.Unmarshal([]byte(lines[0]), &message) != nil || message.ID != 1 || len(message.Result.Content) != 1 ||
		message.Result.Content[0].Type != "text" || json.Unmarshal([]byte(message.Result.Content[0].Text), &payload) != nil {
		t.Fatalf("access.request result is no longer a tool result: %s", lines[0])
	}
	binary, _ := os.Executable()
	word, _ := shellWord(binary, runtime.GOOS == "windows")
	want := word + " --profile default status req-7 --wait"
	if payload["waitCommand"] != want || payload["id"] != "req-7" || payload["status"] != "pending" || payload["approveUrl"] != "https://example.com/?tab=access" {
		t.Fatalf("access.request result did not gain only waitCommand: %v", payload)
	}
}

// The server cannot hand the Agent a command through waitCommand, and an id
// that would change the bridge's own command gets none.
func TestBridgeNeverForwardsAServedWaitCommand(t *testing.T) {
	text := func(payload string) string {
		b, _ := json.Marshal(payload)
		return `{"type":"text","text":` + string(b) + `}`
	}
	served := `"waitCommand":"served-command"`
	content := func(items ...string) string { return `"result":{"content":[` + strings.Join(items, ",") + `]}` }
	for _, reply := range []string{
		content(text(`{"id":"a;b","status":"pending",` + served + `}`)),
		content(text(`{"id":"$(x)","status":"pending",` + served + `}`)),
		content(text(`{"id":"-h","status":"pending",` + served + `}`)),
		content(text(`{"id":7,"status":"pending",` + served + `}`)),
		content(text(`{"status":"pending",` + served + `}`)),
		content(text(`{"id":"req-7",`+served+`}`), text(`{"id":"req-8",`+served+`}`)),
		content(text(`{"id":"a;b","meta":{"nested":[{` + served + `}]}}`)),
		content(text(`{"id":"a;b","WaitCommand":"served-command","WAITCOMMAND":"served-command"}`)),
		content(text(`[{"id":"req-7",` + served + `}]`)),
		`"result":{"content":[` + text(`{"id":"a;b"}`) + `],"structuredContent":{"id":"req-9",` + served + `}}`,
		`"result":{"structuredContent":{` + served + `}}`,
		`"result":{"structuredContent":{"deep":{"list":[{"Waitcommand":"served-command"}]}}}`,
		`"error":{"code":-32000,"message":"failed","data":{` + served + `}}`,
	} {
		fakeStore(t, tokenResponse{AccessToken: "test-only", ExpiresAt: time.Now().Unix() + 600})
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,`+reply+`}`)
		}))
		var out bytes.Buffer
		e := bridge(context.Background(), profile{s.URL, "a"}, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"access.request","arguments":{}}}`+"\n"), &out)
		s.Close()
		if e != nil || strings.Contains(out.String(), "served-command") || strings.Contains(strings.ToLower(out.String()), "waitcommand") {
			t.Errorf("reply %s reached the host as %s (%v)", reply, out.String(), e)
		}
		if !json.Valid(bytes.TrimSpace(out.Bytes())) {
			t.Errorf("reply %s left an invalid reply: %s", reply, out.String())
		}
	}
}
