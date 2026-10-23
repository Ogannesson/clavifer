package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"
)

func printUsage(out io.Writer) {
	fmt.Fprintln(out, `Usage: clavifer [--profile NAME] COMMAND [options]

Commands:
  login       Sign in to one Owner-created installation
  list        List authorized secret and connection metadata
  run         Inject authorized secret fields into a local program
  request     Request access to a secret or connection
  status      Check an access request by ID; --wait blocks until the Owner decides
  doctor      Diagnose login, service and MCP without reading secrets
  profiles list  List local profile metadata without opening the credential store
  logout      Revoke the installation and clear its local login
  mcp         Serve the local MCP bridge on standard input/output
  version     Print the executable version
  help        Show this command list

Use --profile before COMMAND. Default profile: default.
Use clavifer COMMAND --help for login, run, request, status, logout or doctor options.`)
}

// Profiles contain metadata only. Bound reads and fixed errors prevent damaged
// or manually edited configuration from dumping arbitrary file contents.
func readProfile(path string) (profile, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return profile{}, errors.New("profile not found; run clavifer --profile NAME login")
	}
	if err != nil {
		return profile{}, errors.New("profile cannot be read; check local file permissions")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 16*1024+1))
	if err != nil || len(b) > 16*1024 {
		return profile{}, errors.New("profile is unreadable or too large; log in again")
	}
	var p profile
	if json.Unmarshal(b, &p) != nil || !refID.MatchString(p.ClientID) {
		return profile{}, errors.New("profile metadata is invalid; log in again")
	}
	p.Server, err = normalizeServer(p.Server)
	if err != nil {
		return profile{}, errors.New("profile server is invalid; log in again with a trusted HTTPS origin")
	}
	return p, nil
}

type profileSummary struct {
	Name     string `json:"name"`
	Selected bool   `json:"selected"`
	Server   string `json:"server,omitempty"`
	Status   string `json:"status"`
}

func listProfiles() ([]profileSummary, error) {
	dir, err := userConfigDir()
	if err != nil {
		return nil, errors.New("local configuration directory is unavailable")
	}
	base := filepath.Join(dir, "clavifer")
	paths := map[string]string{}
	defaultPath := filepath.Join(base, "profile.json")
	if _, err = os.Stat(defaultPath); err == nil {
		paths["default"] = defaultPath
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("default profile cannot be inspected; check local file permissions")
	}
	entries, err := os.ReadDir(filepath.Join(base, "profiles"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("named profiles cannot be listed; check local file permissions")
	}
	for _, entry := range entries {
		name := strings.TrimSuffix(entry.Name(), ".json")
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || name == "default" || !profileName.MatchString(name) {
			continue
		}
		paths[name] = filepath.Join(base, "profiles", entry.Name())
	}
	result := make([]profileSummary, 0, len(paths))
	for name, path := range paths {
		selected := name == selectedProfile || (runtime.GOOS == "windows" && strings.EqualFold(name, selectedProfile))
		item := profileSummary{Name: name, Selected: selected, Status: "configured"}
		p, err := readProfile(path)
		if err != nil {
			item.Status = "invalid"
		} else {
			item.Server = p.Server
		}
		result = append(result, item)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	return result, nil
}

func cmdProfiles(args []string, out io.Writer) error {
	if len(args) != 1 || args[0] != "list" {
		return errors.New("usage: clavifer [--profile NAME] profiles list")
	}
	profiles, err := listProfiles()
	if err != nil {
		return err
	}
	return writeDiagnostic(out, struct {
		Profiles []profileSummary `json:"profiles"`
	}{profiles})
}

type diagnosticCheck struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type diagnosticReport struct {
	OK              bool              `json:"ok"`
	Version         string            `json:"version"`
	Platform        string            `json:"platform"`
	Profile         string            `json:"profile"`
	Offline         bool              `json:"offline"`
	Server          string            `json:"server,omitempty"`
	ServerVersion   string            `json:"serverVersion,omitempty"`
	ProtocolVersion string            `json:"protocolVersion,omitempty"`
	Checks          []diagnosticCheck `json:"checks"`
	Metadata        *diagnosticCounts `json:"metadata,omitempty"`
	Tools           []string          `json:"tools,omitempty"`
}

type diagnosticCounts struct {
	Secrets     int `json:"secrets"`
	Connections int `json:"connections"`
}

func (r *diagnosticReport) add(name, status, detail string) {
	r.Checks = append(r.Checks, diagnosticCheck{name, status, detail})
	if status == "fail" {
		r.OK = false
	}
}

func diagnosticError(err error) string {
	var api *apiError
	if errors.As(err, &api) {
		switch api.Status {
		case http.StatusUnauthorized:
			return "Login expired or installation revoked; check the management page and log in again."
		case http.StatusForbidden:
			return "The installation lacks the required scope; check its access in the management page."
		case http.StatusTooManyRequests:
			return "The service rate limit was reached; wait before running doctor again."
		}
	}
	return "The check failed; verify network connectivity, service configuration and the selected profile."
}

var releaseVersion = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]{1,40})?$`)
var expectedTools = []string{"access.request", "access.status", "credentials.list", "http.request"}

func diagnose(ctx context.Context, offline bool) diagnosticReport {
	r := diagnosticReport{OK: true, Version: cliVersion, Platform: runtime.GOOS + "/" + runtime.GOARCH, Profile: selectedProfile, Offline: offline, Checks: []diagnosticCheck{}}
	p, err := load()
	if err != nil {
		r.add("profile", "fail", err.Error())
		return r
	}
	r.Server = p.Server
	r.add("profile", "pass", "Valid local metadata; installation identifiers and credential values are omitted from this report.")
	token, err := savedToken(p)
	credentialsReady := err == nil && token.AccessToken != "" && (token.ExpiresAt > time.Now().Unix()+30 || token.RefreshToken != "")
	if errors.Is(err, errNotLoggedIn) {
		r.add("login", "fail", "No login is stored for this profile; run login to sign in.")
	} else if errors.Is(err, errUnreadableLogin) {
		r.add("login", "fail", "The stored login data is damaged; run login again to replace it.")
	} else if err != nil {
		r.add("login", "fail", "The system credential store could not be opened; unlock it, then run doctor again.")
	} else if !credentialsReady {
		r.add("login", "fail", "The stored login is incomplete or fully expired; log in again.")
	} else if token.ExpiresAt <= time.Now().Unix()+30 && offline {
		r.add("login", "warn", "Refresh credentials are available; an online check is required to confirm the session.")
	} else {
		r.add("login", "pass", "Login credentials are available in the system credential store; online validity is checked separately.")
	}
	if offline {
		r.add("server", "skip", "Offline mode: no service requests or token refresh were performed.")
		r.add("metadata", "skip", "Run doctor without --offline to verify authorization.")
		r.add("mcp", "skip", "Run doctor without --offline to verify MCP capabilities.")
		return r
	}
	b, _, err := request(ctx, p, http.MethodGet, "/healthz", nil, false)
	var health struct {
		OK      bool   `json:"ok"`
		Service string `json:"service"`
		Version string `json:"version"`
		Keys    string `json:"keys"`
	}
	var api *apiError
	if errors.As(err, &api) && api.Status == http.StatusServiceUnavailable && api.Code == "invalid_root_key" {
		r.add("server", "fail", "The service's ROOT_KEY secret cannot be parsed, so it answers no requests; its operator must fix the Worker secret.")
		return r
	}
	if err != nil {
		r.add("server", "fail", diagnosticError(err))
		return r
	}
	if json.Unmarshal(b, &health) != nil || health.Service != "clavifer" || !releaseVersion.MatchString(health.Version) || (!health.OK && health.Keys != "mismatch") {
		r.add("server", "fail", "The address did not return a valid Clavifer health response.")
		return r
	}
	r.ServerVersion = health.Version
	if health.Keys == "mismatch" {
		r.add("server", "fail", "The service's root key does not match its database, so it refuses every request; its operator must restore the original ROOT_KEY or rebuild the instance from a backup.")
		return r
	}
	if health.Keys == "uninitialized" {
		r.add("server", "fail", "The service has no Owner yet; its operator must finish setup on the /setup page with the deployment's bootstrap token.")
		return r
	}
	r.add("server", "pass", "The Clavifer service is reachable.")
	if !credentialsReady {
		r.add("metadata", "skip", "A valid system-store login is required.")
		r.add("mcp", "skip", "A valid system-store login is required.")
		return r
	}
	b, _, err = request(ctx, p, http.MethodGet, "/v1/secrets", nil, true)
	var metadata struct {
		Items       []json.RawMessage `json:"items"`
		Connections []json.RawMessage `json:"connections"`
	}
	if err != nil {
		r.add("metadata", "fail", diagnosticError(err))
		return r
	}
	if json.Unmarshal(b, &metadata) != nil || metadata.Items == nil || metadata.Connections == nil {
		r.add("metadata", "fail", "The service returned an invalid metadata response.")
		return r
	}
	r.Metadata = &diagnosticCounts{len(metadata.Items), len(metadata.Connections)}
	r.add("metadata", "pass", "Login accepted; only authorized metadata counts were inspected. Zero resources is valid before grants are added.")
	b, _, err = request(ctx, p, http.MethodPost, "/v1/mcp", map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "clavifer-doctor", "version": cliVersion}}}, true)
	var initialized struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  struct {
			ProtocolVersion string `json:"protocolVersion"`
			Capabilities    struct {
				Tools *json.RawMessage `json:"tools"`
			} `json:"capabilities"`
			ServerInfo struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err != nil {
		r.add("mcp", "fail", diagnosticError(err))
		return r
	}
	if json.Unmarshal(b, &initialized) != nil || initialized.JSONRPC != "2.0" || initialized.ID != 1 || initialized.Result.ProtocolVersion != "2025-11-25" || initialized.Result.ServerInfo.Name != "clavifer" || initialized.Result.Capabilities.Tools == nil {
		r.add("mcp", "fail", "The service did not negotiate the supported MCP protocol and tool capability.")
		return r
	}
	r.ProtocolVersion = initialized.Result.ProtocolVersion
	b, _, err = request(ctx, p, http.MethodPost, "/v1/mcp", map[string]any{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, true)
	var listed struct {
		JSONRPC string `json:"jsonrpc"`
		ID      int    `json:"id"`
		Result  struct {
			Tools []struct {
				Name        string `json:"name"`
				InputSchema struct {
					Type string `json:"type"`
				} `json:"inputSchema"`
				Annotations struct {
					ReadOnlyHint *bool `json:"readOnlyHint"`
				} `json:"annotations"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err != nil {
		r.add("mcp", "fail", diagnosticError(err))
		return r
	}
	if json.Unmarshal(b, &listed) != nil || listed.JSONRPC != "2.0" || listed.ID != 2 {
		r.add("mcp", "fail", "The service returned an invalid MCP tool list.")
		return r
	}
	for _, expected := range expectedTools {
		for _, tool := range listed.Result.Tools {
			if tool.Name == expected && tool.InputSchema.Type == "object" {
				if (expected == "credentials.list" || expected == "access.status") && (tool.Annotations.ReadOnlyHint == nil || !*tool.Annotations.ReadOnlyHint) {
					continue
				}
				r.Tools = append(r.Tools, expected)
				break
			}
		}
	}
	if len(r.Tools) != len(expectedTools) {
		r.add("mcp", "fail", "Required MCP tools, input schemas or read-only annotations are missing; update the service or client.")
		return r
	}
	r.add("mcp", "pass", "All required MCP tools are discoverable. No tools were invoked. Restart the host after changing its MCP configuration.")
	return r
}

func writeDiagnostic(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func cmdDoctor(ctx context.Context, args []string, out io.Writer) error {
	f := flag.NewFlagSet("doctor", flag.ContinueOnError)
	offline := f.Bool("offline", false, "inspect local metadata and system-store login without network requests")
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() != 0 {
		return errors.New("usage: clavifer [--profile NAME] doctor [--offline]")
	}
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	report := diagnose(ctx, *offline)
	if err := writeDiagnostic(out, report); err != nil {
		return err
	}
	if !report.OK {
		return errors.New("doctor found a problem; see the redacted JSON report")
	}
	return nil
}
