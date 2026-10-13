package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/zalando/go-keyring"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"
)

const service = "clavifer"
const maxResponse = 2 * 1024 * 1024
const cliVersion = "0.5.0"
const deviceGrant = "urn:ietf:params:oauth:grant-type:device_code"

type profile struct {
	Server   string `json:"server"`
	ClientID string `json:"client_id"`
}
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"`
	ExpiresAt    int64  `json:"expires_at"`
}

var credentialGet = keyring.Get
var credentialSet = keyring.Set
var credentialDelete = keyring.Delete
var userConfigDir = os.UserConfigDir
var httpClient = &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
var selectedProfile = "default"
var profileName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)

func configPath() (string, error) {
	if !profileName.MatchString(selectedProfile) {
		return "", errors.New("profile must contain 1-64 letters, digits, underscores or hyphens")
	}
	dir, e := userConfigDir()
	if selectedProfile != "default" {
		return filepath.Join(dir, "clavifer", "profiles", selectedProfile+".json"), e
	}
	return filepath.Join(dir, "clavifer", "profile.json"), e
}
func normalizeServer(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil {
		return "", errors.New("server must be a valid HTTPS origin")
	}
	local := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
	if u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || (u.Scheme != "https" && !(u.Scheme == "http" && local)) {
		return "", errors.New("server must be an HTTPS origin (HTTP only on localhost)")
	}
	return strings.TrimRight(u.String(), "/"), nil
}
func load() (profile, error) {
	path, e := configPath()
	if e != nil {
		return profile{}, e
	}
	return readProfile(path)
}
func save(p profile) error {
	path, e := configPath()
	if e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	b, e := json.Marshal(p)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), "profile-*.tmp")
	if e != nil {
		return e
	}
	tmp := f.Name()
	// Preserve incomplete metadata writes for diagnosis. No credential values are
	// ever written here, and a successful rename leaves no temporary file.
	if e = f.Chmod(0600); e != nil {
		f.Close()
		return e
	}
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(tmp, path)
}
func credentialKey(p profile) string { return p.Server + "/" + p.ClientID }
func storeToken(p profile, t tokenResponse) error {
	b, e := json.Marshal(t)
	if e != nil {
		return e
	}
	if e = credentialSet(service, credentialKey(p), string(b)); e != nil {
		return fmt.Errorf("system credential store unavailable: %w", e)
	}
	return nil
}

// Separated so the caller can suggest logging in instead of repairing a store
// that is working correctly and simply holds nothing for this installation.
var errNotLoggedIn = errors.New("not logged in; run login")

// A store that hands back something unparseable is working; the saved blob is
// the damaged part, and logging in again replaces it.
var errUnreadableLogin = errors.New("stored login is unreadable; run login again")

func savedToken(p profile) (tokenResponse, error) {
	s, e := credentialGet(service, credentialKey(p))
	if errors.Is(e, keyring.ErrNotFound) {
		return tokenResponse{}, errNotLoggedIn
	}
	if e != nil {
		return tokenResponse{}, fmt.Errorf("system credential store unavailable: %w", e)
	}
	var t tokenResponse
	if json.Unmarshal([]byte(s), &t) != nil {
		return tokenResponse{}, errUnreadableLogin
	}
	return t, nil
}
func readResponse(r *http.Response) ([]byte, error) {
	defer r.Body.Close()
	b, e := io.ReadAll(io.LimitReader(r.Body, maxResponse+1))
	if e != nil {
		return nil, e
	}
	if len(b) > maxResponse {
		return nil, errors.New("response exceeds 2 MiB")
	}
	return b, nil
}

type apiError struct {
	Status     int
	Code       string
	RetryAfter int
}

func (e *apiError) Error() string { return fmt.Sprintf("server returned %d (%s)", e.Status, e.Code) }
func decodeError(r *http.Response, b []byte) error {
	var v struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(b, &v)
	if !regexp.MustCompile(`^[a-zA-Z0-9_:-]{1,100}$`).MatchString(v.Error) {
		v.Error = "request_failed"
	}
	retryAfter, _ := strconv.Atoi(r.Header.Get("retry-after"))
	return &apiError{Status: r.StatusCode, Code: v.Error, RetryAfter: retryAfter}
}
func postForm(ctx context.Context, p profile, values url.Values) (tokenResponse, error) {
	req, e := http.NewRequestWithContext(ctx, "POST", p.Server+"/api/auth/oauth2/token", strings.NewReader(values.Encode()))
	if e != nil {
		return tokenResponse{}, e
	}
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	if values.Get("grant_type") == deviceGrant {
		// Polling is safe to resend, so let the transport resend it when the reused
		// connection turns out to be closed. Local wrangler dev drops idle
		// connections after 5 s, the polling interval. An empty value keeps the
		// header off the wire.
		req.Header["Idempotency-Key"] = nil
	}
	r, e := httpClient.Do(req)
	if e != nil {
		return tokenResponse{}, errors.New("token endpoint unavailable")
	}
	b, e := readResponse(r)
	if e != nil {
		return tokenResponse{}, e
	}
	if r.StatusCode != 200 {
		return tokenResponse{}, decodeError(r, b)
	}
	var t tokenResponse
	if e = json.Unmarshal(b, &t); e != nil {
		return t, errors.New("invalid token response")
	}
	if t.AccessToken == "" || t.ExpiresIn <= 0 {
		return t, errors.New("incomplete token response")
	}
	t.ExpiresAt = time.Now().Unix() + t.ExpiresIn
	return t, nil
}
func validToken(ctx context.Context, p profile) (tokenResponse, error) {
	unlock, e := tokenLock(credentialKey(p))
	if e != nil {
		return tokenResponse{}, e
	}
	defer unlock()
	t, e := savedToken(p)
	if e != nil {
		return t, e
	}
	if t.ExpiresAt > time.Now().Unix()+30 {
		return t, nil
	}
	if t.RefreshToken == "" {
		return t, errors.New("session expired; log in again")
	}
	next, e := postForm(ctx, p, url.Values{"grant_type": {"refresh_token"}, "client_id": {p.ClientID}, "refresh_token": {t.RefreshToken}, "resource": {p.Server + "/v1"}})
	if e != nil {
		return tokenResponse{}, e
	}
	if next.RefreshToken == "" {
		next.RefreshToken = t.RefreshToken
	}
	if e = storeToken(p, next); e != nil {
		// The server has already rotated the refresh token, so the copy still in
		// the store is dead and continuing would spend a credential we cannot keep.
		return tokenResponse{}, fmt.Errorf("refreshed login could not be saved to the system credential store; run login again: %w", e)
	}
	return next, nil
}

// Only these requests change server state. Every other failure is a transport
// problem the caller may repeat safely.
func writesState(method, path string) bool {
	return method != http.MethodGet && method != http.MethodHead && (path == "/v1/access-requests" || path == "/v1/logout" || path == "/v1/mcp")
}
func request(ctx context.Context, p profile, method, path string, body any, authenticated bool) ([]byte, int, error) {
	var reader io.Reader
	if body != nil {
		b, e := json.Marshal(body)
		if e != nil {
			return nil, 0, e
		}
		reader = bytes.NewReader(b)
	}
	req, e := http.NewRequestWithContext(ctx, method, p.Server+path, reader)
	if e != nil {
		return nil, 0, e
	}
	if body != nil {
		req.Header.Set("content-type", "application/json")
	}
	if authenticated {
		t, e := validToken(ctx, p)
		if e != nil {
			return nil, 0, e
		}
		req.Header.Set("authorization", "Bearer "+t.AccessToken)
	}
	req.Header.Set("accept", "application/json, text/event-stream")
	req.Header.Set("mcp-protocol-version", "2025-11-25")
	r, e := httpClient.Do(req)
	if e != nil {
		if writesState(method, path) {
			return nil, 0, errors.New("request failed; a write may have an unknown outcome, do not retry automatically")
		}
		return nil, 0, errors.New("service unavailable; check the server address and network connection")
	}
	b, e := readResponse(r)
	if e != nil {
		return nil, r.StatusCode, e
	}
	if r.StatusCode >= 300 {
		return nil, r.StatusCode, decodeError(r, b)
	}
	return b, r.StatusCode, nil
}

func cmdLogin(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("login", flag.ContinueOnError)
	server := f.String("server", "", "service HTTPS origin")
	client := f.String("client-id", "", "unique installation client id")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("usage: clavifer login --server HTTPS_ORIGIN --client-id INSTALLATION_ID")
	}
	normalized, e := normalizeServer(*server)
	if e != nil {
		return e
	}
	if *client == "" {
		return errors.New("--client-id is required; create one installation in the management page")
	}
	if !refID.MatchString(*client) {
		return errors.New("--client-id must contain 1-100 letters, digits, underscores or hyphens")
	}
	p := profile{normalized, *client}
	b, _, e := request(ctx, p, "POST", "/api/auth/device/code", map[string]string{"client_id": p.ClientID, "scope": "offline_access metadata:list secret:read connection:invoke access:request", "resource": p.Server + "/v1"}, false)
	if e != nil {
		return e
	}
	var d struct {
		DeviceCode string `json:"device_code"`
		UserCode   string `json:"user_code"`
		URI        string `json:"verification_uri"`
		ExpiresIn  int    `json:"expires_in"`
		Interval   int    `json:"interval"`
	}
	if e = json.Unmarshal(b, &d); e != nil {
		return e
	}
	if d.DeviceCode == "" || d.UserCode == "" || d.ExpiresIn <= 0 {
		return errors.New("invalid device response")
	}
	verification, e := url.Parse(d.URI)
	if e != nil || verification.Scheme+"://"+verification.Host != p.Server {
		return errors.New("untrusted verification URL")
	}
	fmt.Fprintf(os.Stderr, "Open %s and enter code %s. Approve only this installation.\n", d.URI, d.UserCode)
	if d.Interval < 5 {
		d.Interval = 5
	}
	deadline := time.Now().Add(time.Duration(d.ExpiresIn) * time.Second)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Duration(d.Interval) * time.Second):
		}
		t, e := postForm(ctx, p, url.Values{"grant_type": {deviceGrant}, "device_code": {d.DeviceCode}, "client_id": {p.ClientID}})
		if e == nil {
			if e = storeToken(p, t); e != nil {
				return e
			}
			if e = save(p); e != nil {
				return e
			}
			fmt.Fprintln(os.Stderr, "Logged in. Resource grants are managed separately in the web page.")
			return nil
		}
		var ae *apiError
		if errors.As(e, &ae) {
			if ae.Status == http.StatusTooManyRequests {
				d.Interval = max(d.Interval, min(ae.RetryAfter, 3600))
				continue
			}
			if ae.Code == "authorization_pending" {
				continue
			}
			if ae.Code == "slow_down" {
				d.Interval += 5
				continue
			}
		}
		return e
	}
	return errors.New("device code expired; start login again")
}
func cmdList(ctx context.Context) error {
	p, e := load()
	if e != nil {
		return e
	}
	b, _, e := request(ctx, p, "GET", "/v1/secrets", nil, true)
	if e == nil {
		fmt.Println(string(b))
	}
	return e
}

var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
var fieldName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]{0,63}$`)
var refID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,100}$`)

func parseBind(value string) (string, string, string, error) {
	parts := strings.SplitN(value, "=", 2)
	if len(parts) != 2 || !envName.MatchString(parts[0]) {
		return "", "", "", errors.New("binding must be ENV=secret-id.field")
	}
	ref := strings.SplitN(parts[1], ".", 2)
	if len(ref) != 2 || !refID.MatchString(ref[0]) || !fieldName.MatchString(ref[1]) {
		return "", "", "", errors.New("binding must reference secret-id.field")
	}
	return parts[0], ref[0], ref[1], nil
}

func parseFields(value string) ([]string, error) {
	fields := strings.Split(value, ",")
	for _, field := range fields {
		if !fieldName.MatchString(field) {
			return nil, errors.New("--fields must be a comma-separated list of field names")
		}
	}
	if len(fields) > 20 {
		return nil, errors.New("--fields accepts at most 20 field names")
	}
	return fields, nil
}

// How long an interrupted child may take to finish before it is killed.
var childWaitDelay = 10 * time.Second

// A child that cleaned up and exited zero still ended because of an interrupt,
// and a shell wrapping this command reads that from the exit status alone.
var errInterrupted = errors.New("interrupted")

type bindings []string

func (b *bindings) String() string     { return "credential bindings" }
func (b *bindings) Set(v string) error { *b = append(*b, v); return nil }
func cmdRun(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("run", flag.ContinueOnError)
	var binds bindings
	f.Var(&binds, "bind", "ENV=secret-id.field; repeat for multiple fields")
	if e := f.Parse(args); e != nil {
		return e
	}
	if len(binds) == 0 || f.NArg() == 0 {
		return errors.New("usage: clavifer run --bind ENV=secret-id.field -- command [args]")
	}
	type parsedBinding struct{ name, secretID, field string }
	parsed := make([]parsedBinding, 0, len(binds))
	seen := map[string]bool{}
	for _, binding := range binds {
		name, sid, field, e := parseBind(binding)
		if e != nil {
			return e
		}
		if seen[strings.ToUpper(name)] {
			return errors.New("duplicate environment binding")
		}
		seen[strings.ToUpper(name)] = true
		parsed = append(parsed, parsedBinding{name, sid, field})
	}
	// Ask each secret only for the fields this command actually binds.
	requested := make(map[string][]string)
	for _, binding := range parsed {
		if !slices.Contains(requested[binding.secretID], binding.field) {
			requested[binding.secretID] = append(requested[binding.secretID], binding.field)
		}
	}
	p, e := load()
	if e != nil {
		return e
	}
	env := os.Environ()
	// Reuse one response per secret so its fields belong to the same version.
	values := make(map[string]map[string]string)
	for _, binding := range parsed {
		name, sid, field := binding.name, binding.secretID, binding.field
		if _, loaded := values[sid]; !loaded {
			b, _, e := request(ctx, p, "POST", "/v1/secrets/"+url.PathEscape(sid)+"/read", map[string][]string{"fields": requested[sid]}, true)
			if e != nil {
				return e
			}
			var value struct {
				Values map[string]string `json:"values"`
			}
			if e = json.Unmarshal(b, &value); e != nil {
				return errors.New("invalid secret response")
			}
			values[sid] = value.Values
		}
		secret, ok := values[sid][field]
		if !ok {
			return errors.New("secret field not found")
		}
		filtered := env[:0]
		for _, v := range env {
			n, _, _ := strings.Cut(v, "=")
			if !strings.EqualFold(n, name) {
				filtered = append(filtered, v)
			}
		}
		env = append(filtered, name+"="+secret)
	}
	cmd := exec.CommandContext(ctx, f.Arg(0), f.Args()[1:]...)
	cmd.Env = env
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	// A terminal delivers Ctrl+C to the whole group, so a child started from one
	// has already been asked to stop and cancelling would only cut its cleanup
	// short. Without a terminal, such as an interrupt sent straight to this
	// process, nothing reaches the child and WaitDelay is the only stop.
	cmd.Cancel = func() error { return nil }
	cmd.WaitDelay = childWaitDelay
	e = cmd.Run()
	// os/exec reports the cancellation itself only when the child exited zero.
	// A cancellation before the child started has no exit status to pass on.
	if errors.Is(e, context.Canceled) && cmd.ProcessState != nil {
		return errInterrupted
	}
	return e
}
func cmdRequest(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("request", flag.ContinueOnError)
	sid := f.String("secret", "", "secret id")
	cid := f.String("connection", "", "connection id")
	reason := f.String("reason", "", "reason for Owner")
	fields := f.String("fields", "", "comma-separated secret fields; omit to request every field")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("usage: clavifer request (--secret ID [--fields a,b] | --connection ID) --reason TEXT")
	}
	if (*sid == "") == (*cid == "") {
		return errors.New("specify exactly one --secret or --connection")
	}
	kind, rid, permission := "secret", *sid, "secret:read"
	if *cid != "" {
		kind, rid, permission = "connection", *cid, "connection:invoke"
	}
	if !refID.MatchString(rid) {
		return errors.New("invalid resource id")
	}
	grant := map[string]any{"resourceType": kind, "resourceId": rid, "permission": permission}
	if *fields != "" {
		if kind != "secret" {
			return errors.New("--fields applies to --secret only")
		}
		names, e := parseFields(*fields)
		if e != nil {
			return e
		}
		grant["fields"] = names
	}
	p, e := load()
	if e != nil {
		return e
	}
	b, _, e := request(ctx, p, "POST", "/v1/access-requests", map[string]any{"requested": map[string]any{"grants": []map[string]any{grant}}, "reason": *reason}, true)
	if e == nil {
		fmt.Println(string(b))
	}
	return e
}

// How often status --wait asks again; a rate-limited answer waits as long as
// the server asks, up to an hour.
var statusInterval = 5 * time.Second

// A request id also travels as a command argument in waitCommand, so it must
// not start like an option.
var requestID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,99}$`)

// The Owner had not decided when --timeout ran out. Its own exit status lets a
// host that ran the wait in the background tell this apart from a failure.
var errStillPending = errors.New("still waiting for the Owner; run the same command again, or ask the user instead")

func cmdStatus(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("status", flag.ContinueOnError)
	wait := f.Bool("wait", false, "keep checking until the request is no longer pending")
	// Shorter than the 30 minutes a Claude Code background command may run.
	timeout := f.Duration("timeout", 25*time.Minute, "how long --wait keeps checking")
	if e := f.Parse(args); e != nil {
		return e
	}
	// The request id may come before or after the options.
	rid := f.Arg(0)
	if f.NArg() > 0 {
		if e := f.Parse(f.Args()[1:]); e != nil {
			return e
		}
	}
	if f.NArg() != 0 || !requestID.MatchString(rid) {
		return errors.New("usage: clavifer status REQUEST_ID [--wait [--timeout 25m]]")
	}
	if *timeout <= 0 {
		return errors.New("--timeout must be positive")
	}
	timeoutSet := false
	f.Visit(func(option *flag.Flag) { timeoutSet = timeoutSet || option.Name == "timeout" })
	if timeoutSet && !*wait {
		return errors.New("--timeout applies to --wait only")
	}
	p, e := load()
	if e != nil {
		return e
	}
	deadline := time.Now().Add(*timeout)
	for {
		b, _, e := request(ctx, p, "GET", "/v1/access-requests/"+rid, nil, true)
		delay := statusInterval
		var ae *apiError
		switch {
		case ctx.Err() != nil:
			return errInterrupted
		case e == nil:
			var s struct {
				Status string `json:"status"`
			}
			_ = json.Unmarshal(b, &s)
			if !*wait || s.Status != "pending" {
				fmt.Fprintln(out, string(b))
				return nil
			}
		case *wait && errors.As(e, &ae) && ae.Status == http.StatusTooManyRequests:
			delay = max(delay, time.Duration(min(ae.RetryAfter, 3600))*time.Second)
			// Not a pending answer, so it must not read as "still waiting for the Owner".
			if time.Now().Add(delay).After(deadline) {
				return fmt.Errorf("rate limited beyond --timeout, so the decision was not checked; run the same command again later: %w", e)
			}
		default:
			return e
		}
		if time.Now().Add(delay).After(deadline) {
			return errStillPending
		}
		select {
		case <-ctx.Done():
			return errInterrupted
		case <-time.After(delay):
		}
	}
}
func cmdLogout(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("logout", flag.ContinueOnError)
	localOnly := f.Bool("local", false, "clear local login only; revoke the installation in the management page")
	if e := f.Parse(args); e != nil {
		return e
	}
	if f.NArg() != 0 {
		return errors.New("usage: clavifer logout [--local]")
	}
	p, e := load()
	if e != nil {
		return e
	}
	if !*localOnly {
		_, _, e = request(ctx, p, "POST", "/v1/logout", nil, true)
		if e != nil {
			return fmt.Errorf("remote revocation failed; revoke this installation in the management page, then use logout --local: %w", e)
		}
	} else {
		fmt.Fprintln(os.Stderr, "Clearing local login only. This does not revoke remote access; revoke the installation in the management page.")
	}
	if e = credentialDelete(service, credentialKey(p)); e != nil && !errors.Is(e, keyring.ErrNotFound) {
		return e
	}
	path, e := configPath()
	if e == nil {
		e = archiveProfile(path)
	}
	return e
}

// A line is one JSON-RPC message or a batch array. Both shapes are forwarded
// unchanged; the ids of the requests inside are kept so a transport failure can
// answer each one instead of leaving the host waiting for a reply. A response
// travelling the other way carries an id but no method and must not be answered.
func requestIDs(line []byte) (ids []json.RawMessage, batch bool, err error) {
	collect := func(message map[string]json.RawMessage) {
		if message["id"] != nil && message["method"] != nil {
			ids = append(ids, message["id"])
		}
	}
	var single map[string]json.RawMessage
	if json.Unmarshal(line, &single) == nil {
		collect(single)
		return ids, false, nil
	}
	var many []map[string]json.RawMessage
	if json.Unmarshal(line, &many) != nil {
		return nil, false, errors.New("invalid MCP JSON input")
	}
	for _, message := range many {
		collect(message)
	}
	return ids, true, nil
}
func emit(writer *bufio.Writer, b []byte) error {
	if _, e := writer.Write(append(b, '\n')); e != nil {
		return e
	}
	return writer.Flush()
}

var plainWord = regexp.MustCompile(`^[A-Za-z0-9_./:-]+$`)

// The executable path as one shell word. On Windows forward slashes keep it
// intact in Git Bash, which drops unquoted backslashes, while PowerShell and
// Windows itself accept them; a path that needs quoting gets Windows double
// quotes there and POSIX single quotes elsewhere. PowerShell and Git Bash still
// expand $ and ` inside double quotes, so a Windows path holding either has no
// safe word and reports false.
func shellWord(path string, windows bool) (string, bool) {
	if windows {
		path = strings.ReplaceAll(path, `\`, "/")
	}
	switch {
	case plainWord.MatchString(path):
		return path, true
	case windows:
		return `"` + path + `"`, !strings.ContainsAny(path, "$`")
	default:
		return "'" + strings.ReplaceAll(path, "'", `'\''`) + "'", true
	}
}

// The one change the bridge makes to a result: a successful access.request
// gains waitCommand, a local command that blocks until the Owner decides, so a
// host can run it and continue when it exits. Anything else passes unchanged.
func isAccessRequest(line []byte) bool {
	var m struct {
		Method string `json:"method"`
		Params struct {
			Name string `json:"name"`
		} `json:"params"`
	}
	return json.Unmarshal(line, &m) == nil && m.Method == "tools/call" && m.Params.Name == "access.request"
}
func waitCommand(id string) (string, bool) {
	executable, e := os.Executable()
	if e != nil || !requestID.MatchString(id) {
		return "", false
	}
	word, ok := shellWord(executable, runtime.GOOS == "windows")
	return word + " --profile " + selectedProfile + " status " + id + " --wait", ok
}

// One complete JSON value, numbers kept as written.
func decodeJSON(b []byte) (any, bool) {
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil || d.Decode(new(any)) != io.EOF {
		return nil, false
	}
	return v, true
}

// Removes every waitCommand key, in any letter case and at any depth, also
// inside JSON carried as tool text; reports whether anything was removed.
func stripWaitCommand(v any) bool {
	removed := false
	switch v := v.(type) {
	case map[string]any:
		for key, child := range v {
			if strings.EqualFold(key, "waitCommand") {
				delete(v, key)
				removed = true
			} else if stripWaitCommand(child) {
				removed = true
			}
		}
		if text, ok := v["text"].(string); ok && v["type"] == "text" {
			if inner, ok := decodeJSON([]byte(text)); ok && stripWaitCommand(inner) {
				b, _ := json.Marshal(inner)
				v["text"] = string(b)
				removed = true
			}
		}
	case []any:
		for _, child := range v {
			if stripWaitCommand(child) {
				removed = true
			}
		}
	}
	return removed
}

// An Agent runs waitCommand as given, so only the bridge may supply one: every
// waitCommand the server's response carries is removed first, and the bridge's
// own is added only to the text of a single result whose id is safe to pass on.
func withWaitCommand(b []byte) []byte {
	v, ok := decodeJSON(b)
	if !ok {
		return b
	}
	changed := stripWaitCommand(v)
	message, _ := v.(map[string]any)
	result, _ := message["result"].(map[string]any)
	if content, _ := result["content"].([]any); len(content) == 1 {
		item, _ := content[0].(map[string]any)
		text, _ := item["text"].(string)
		inner, _ := decodeJSON([]byte(text))
		payload, _ := inner.(map[string]any)
		id, _ := payload["id"].(string)
		if command, ok := waitCommand(id); ok {
			payload["waitCommand"] = command
			updated, _ := json.Marshal(payload)
			item["text"] = string(updated)
			changed = true
		}
	}
	if !changed {
		return b
	}
	b, _ = json.Marshal(v)
	return b
}
func bridge(ctx context.Context, p profile, in io.Reader, out io.Writer) error {
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 65536), maxResponse)
	writer := bufio.NewWriter(out)
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		ids, batch, e := requestIDs(line)
		if e != nil {
			// Ending the bridge here would cost the host every tool over one bad
			// line, so report the parse failure in protocol terms and keep serving.
			parseError, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": nil, "error": map[string]any{"code": -32700, "message": e.Error()}})
			if e = emit(writer, parseError); e != nil {
				return e
			}
			continue
		}
		b, status, e := request(ctx, p, "POST", "/v1/mcp", json.RawMessage(line), true)
		if e != nil {
			if len(ids) == 0 {
				fmt.Fprintln(os.Stderr, "MCP notification failed")
				continue
			}
			failures := make([]any, 0, len(ids))
			for _, id := range ids {
				failures = append(failures, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": -32000, "message": e.Error()}})
			}
			if batch {
				b, _ = json.Marshal(failures)
			} else {
				b, _ = json.Marshal(failures[0])
			}
			status = 200
		} else if isAccessRequest(line) {
			b = withWaitCommand(b)
		}
		if status != 202 && len(b) > 0 {
			if e = emit(writer, b); e != nil {
				return e
			}
		}
	}
	return scanner.Err()
}
func execute(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("clavifer", flag.ContinueOnError)
	f.Usage = func() { printUsage(f.Output()) }
	name := f.String("profile", "default", "named installation profile")
	if e := f.Parse(args); e != nil {
		return e
	}
	if !profileName.MatchString(*name) {
		return errors.New("invalid profile name")
	}
	selectedProfile = *name
	args = f.Args()
	if len(args) == 0 {
		printUsage(os.Stderr)
		return errors.New("a command is required")
	}
	switch args[0] {
	case "help":
		if len(args) != 1 {
			return errors.New("use clavifer COMMAND --help for command options")
		}
		printUsage(os.Stdout)
		return nil
	case "version":
		if len(args) != 1 {
			return errors.New("usage: clavifer version")
		}
		fmt.Println("clavifer " + cliVersion)
		return nil
	case "doctor":
		return cmdDoctor(ctx, args[1:], os.Stdout)
	case "profiles":
		return cmdProfiles(args[1:], os.Stdout)
	case "login":
		return cmdLogin(ctx, args[1:])
	case "list":
		if len(args) != 1 {
			return errors.New("usage: clavifer list")
		}
		return cmdList(ctx)
	case "run":
		return cmdRun(ctx, args[1:])
	case "request":
		return cmdRequest(ctx, args[1:])
	case "logout":
		return cmdLogout(ctx, args[1:])
	case "status":
		return cmdStatus(ctx, args[1:], os.Stdout)
	case "mcp":
		if len(args) != 1 {
			return errors.New("usage: clavifer mcp")
		}
		p, e := load()
		if e != nil {
			return e
		}
		return bridge(ctx, p, os.Stdin, os.Stdout)
	default:
		return errors.New("unknown command; run clavifer help")
	}
}

// Exit status for a failed command: 130 when the run ended in an interrupt, 124
// when status --wait ran out of time, the child's own status when it produced
// one, and 1 for anything else. Only the timeout and that last case carry a
// message worth printing.
func exitCode(e error) (int, bool) {
	if errors.Is(e, errInterrupted) {
		return 130, false
	}
	if errors.Is(e, errStillPending) {
		return 124, true
	}
	var child *exec.ExitError
	if errors.As(e, &child) {
		if code := child.ExitCode(); code > 0 {
			return code, false
		}
		return 1, false
	}
	return 1, true
}
func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if e := execute(ctx, os.Args[1:]); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return
		}
		code, report := exitCode(e)
		if report {
			fmt.Fprintln(os.Stderr, e)
		}
		os.Exit(code)
	}
}
