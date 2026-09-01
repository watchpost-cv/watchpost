package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// watchpostUnitMarker marks unit files written by `watchpost service`.
const watchpostUnitMarker = "# Managed by watchpost. Do not edit manually."

// watchpostManagedPrefix introduces the versioned integrity header. The header
// is followed by a SHA-256 of everything below it (managed metadata plus the
// unit body), so any hand edit is detected on the next write, action or
// uninstall.
const watchpostManagedPrefix = "# watchpost-managed: "

// watchpostHealthPath is the public, read-only liveness endpoint the service
// health check targets.
const watchpostHealthPath = "/healthz"

var (
	errNotManaged = errors.New("not a managed unit")
	errMalformed  = errors.New("malformed managed unit header")
	errModified   = errors.New("managed unit body no longer matches its recorded checksum")
)

// serviceRunner abstracts systemctl/journalctl so the CLI is testable without
// touching a real systemd user manager. Run returns the captured combined
// output, the process exit code (0 on success, -1 when the command could not
// be launched) and a launch error only.
type serviceRunner interface {
	Run(name string, args ...string) (string, int, error)
	Stream(name string, args ...string) (int, error)
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) (string, int, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return string(out), ee.ExitCode(), nil
	}
	return string(out), -1, err
}

func (execRunner) Stream(name string, args ...string) (int, error) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err == nil {
		return 0, nil
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode(), nil
	}
	return -1, err
}

type serviceManager struct {
	unitName string
	unitPath string
	exe      string
	run      serviceRunner
}

type unitMeta struct {
	listen   string
	data     string
	envfile  string
	secure   bool
	health   string
}

// validateEnvFile validates an EnvironmentFile path for the service unit:
// absolute, a regular non-symlink file with exactly owner-only 0600
// permissions, owned by the invoking user, and free of systemd specifier and
// control characters. Secret values are never read or embedded.
func validateEnvFile(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("environment file %q must be an absolute path", path)
	}
	if err := validateNoControl(path, "environment file"); err != nil {
		return err
	}
	if strings.ContainsAny(path, "%") {
		return fmt.Errorf("environment file %q must not contain systemd specifiers (%% )", path)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("environment file: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("environment file %q must not be a symlink", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("environment file %q must be a regular file", path)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("environment file %q must have exactly 0600 permissions (owner read/write only)", path)
	}
	if err := fileOwnerOK(info); err != nil {
		return fmt.Errorf("environment file %q: %w", path, err)
	}
	return nil
}

// prepareDataDir creates the service data directory with owner-only permissions
// and refuses symlinks, non-directories, unsafe permissions or wrong ownership.
func prepareDataDir(path string) error {
	if err := os.MkdirAll(path, 0700); err != nil {
		return fmt.Errorf("cannot create data directory %q: %w", path, err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("data directory %q: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("data directory %q must not be a symlink", path)
	}
	if !info.IsDir() {
		return fmt.Errorf("data directory %q is not a directory", path)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("data directory %q must not be group- or world-writable", path)
	}
	if err := fileOwnerOK(info); err != nil {
		return fmt.Errorf("data directory %q: %w", path, err)
	}
	return nil
}

// validateReadWritePath validates a data directory for the ReadWritePaths=
// directive: absolute, free of control characters, systemd specifiers, quotes
// and backslashes, and not starting with a special path-list prefix.
func validateReadWritePath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("data directory %q must be an absolute path", path)
	}
	if err := validateNoControl(path, "data directory"); err != nil {
		return err
	}
	if strings.ContainsAny(path, "%") {
		return fmt.Errorf("data directory %q must not contain systemd specifiers (%% )", path)
	}
	if strings.ContainsAny(path, `"\`) {
		return fmt.Errorf("data directory %q cannot be safely quoted in ReadWritePaths", path)
	}
	if len(path) > 0 && strings.ContainsRune("-+!~", rune(path[0])) {
		return fmt.Errorf("data directory %q starts with a ReadWritePaths special prefix; use a plain absolute path", path)
	}
	return nil
}

func userUnitPath(unitName string) string {
	base, err := os.UserConfigDir()
	if err != nil {
		base = os.Getenv("HOME")
	}
	return filepath.Join(base, "systemd", "user", unitName)
}

func (m *serviceManager) systemctl(args ...string) (string, int, error) {
	return m.run.Run("systemctl", append([]string{"--user"}, args...)...)
}

// svcState is a deliberately resolved systemd state category that separates
// command-result validation from the lifecycle meaning uninstall needs.
type svcState string

const (
	stateActive     svcState = "active"
	stateReloading  svcState = "reloading"
	stateRefreshing svcState = "refreshing"
	stateTransition svcState = "transitioning"
	stateInactive   svcState = "inactive"
	stateUnknown    svcState = "unknown"
	stateEnabled    svcState = "enabled"
	stateNotEnabled svcState = "not-enabled"
	stateMasked     svcState = "masked"
)

func stateName(s svcState) string { return string(s) }

// exitExpect describes how strongly an output word's exit code is fixed by the
// systemd contract across the supported range (systemd 252 through current).
type exitExpect int

const (
	exitZero     exitExpect = iota // the state must exit 0
	exitNonzero                    // the state must exit nonzero
	exitEither                     // the exit code varies across versions
)

func classifyActive(word string) (svcState, exitExpect, bool) {
	switch word {
	case "active":
		return stateActive, exitZero, true
	case "reloading":
		return stateReloading, exitZero, true
	case "refreshing":
		return stateRefreshing, exitEither, true
	case "inactive", "dead", "failed":
		return stateInactive, exitNonzero, true
	case "activating", "deactivating", "maintenance":
		return stateTransition, exitNonzero, true
	case "not-found", "unknown":
		return stateUnknown, exitNonzero, true
	}
	return "", 0, false
}

func classifyEnabled(word string) (svcState, exitExpect, bool) {
	switch word {
	case "enabled", "enabled-runtime":
		return stateEnabled, exitZero, true
	case "static", "alias", "indirect", "generated":
		return stateNotEnabled, exitZero, true
	case "disabled", "linked", "linked-runtime", "transient":
		return stateNotEnabled, exitNonzero, true
	case "masked", "masked-runtime":
		return stateMasked, exitNonzero, true
	case "not-found":
		return stateNotEnabled, exitNonzero, true
	case "unknown":
		return stateUnknown, exitNonzero, true
	}
	return "", 0, false
}

func (m *serviceManager) queryState(verb string) (svcState, error) {
	out, code, err := m.systemctl(verb, m.unitName)
	if err != nil {
		return "", fmt.Errorf("cannot run systemctl %s %s: %w", verb, m.unitName, err)
	}
	word := strings.TrimSpace(out)
	var st svcState
	var expect exitExpect
	var ok bool
	switch verb {
	case "is-active":
		st, expect, ok = classifyActive(word)
	case "is-enabled":
		st, expect, ok = classifyEnabled(word)
	}
	if !ok {
		return "", fmt.Errorf("systemctl %s %s returned unrecognized state %q (exit %d)", verb, m.unitName, word, code)
	}
	switch expect {
	case exitZero:
		if code != 0 {
			return "", fmt.Errorf("systemctl %s %s reported %q but exited %d; inconsistent state result", verb, m.unitName, word, code)
		}
	case exitNonzero:
		if code == 0 {
			return "", fmt.Errorf("systemctl %s %s reported %q but exited 0; inconsistent state result", verb, m.unitName, word)
		}
	}
	return st, nil
}

func bounded(s string) string {
	const max = 2000
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func (m *serviceManager) systemctlSuccess(args ...string) error {
	out, code, err := m.systemctl(args...)
	if err != nil {
		return fmt.Errorf("cannot run systemctl %s: %w", strings.Join(args, " "), err)
	}
	if code != 0 {
		return fmt.Errorf("systemctl %s exited %d: %s", strings.Join(args, " "), code, bounded(strings.TrimSpace(out)))
	}
	return nil
}

func validateNoControl(v, what string) error {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return fmt.Errorf("%s %q contains a control character", what, v)
		}
	}
	return nil
}

func systemdQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '%':
			b.WriteString("%%")
		case '"', '\\', '$', '`':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func renderWatchpostUnitBody(exe, listen, dataDir string, secureCookies bool, envfile string) string {
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Watchpost monitoring service\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("ExecStart=" + systemdQuote(exe))
	b.WriteString(" " + systemdQuote("--listen") + " " + systemdQuote(listen))
	b.WriteString(" " + systemdQuote("--data-dir") + " " + systemdQuote(dataDir))
	if secureCookies {
		b.WriteString(" " + systemdQuote("--secure-cookies"))
	}
	b.WriteString("\n")
	b.WriteString("WorkingDirectory=" + systemdQuote(filepath.Dir(exe)) + "\n")
	b.WriteString("Restart=on-failure\n")
	b.WriteString("Environment=HOME=%h\n")
	b.WriteString("NoNewPrivileges=true\n")
	b.WriteString("PrivateTmp=true\n")
	b.WriteString("ProtectSystem=strict\n")
	b.WriteString("ProtectHome=read-only\n")
	b.WriteString("ReadWritePaths=" + systemdQuote(dataDir) + "\n")
	if envfile != "" {
		b.WriteString("EnvironmentFile=" + systemdQuote(envfile) + "\n")
	}
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=default.target\n")
	return b.String()
}

func buildWatchpostUnit(exe, listen, dataDir string, secureCookies bool, envfile string) string {
	meta := "# watchpost-listen: " + listen + "\n# watchpost-data: " + dataDir + "\n"
	if secureCookies {
		meta += "# watchpost-secure-cookies: 1\n"
	}
	if envfile != "" {
		meta += "# watchpost-envfile: " + envfile + "\n"
	}
	meta += "# watchpost-health: " + watchpostHealthPath + "\n"
	content := meta + renderWatchpostUnitBody(exe, listen, dataDir, secureCookies, envfile)
	sum := sha256.Sum256([]byte(content))
	header := watchpostUnitMarker + "\n" + watchpostManagedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n"
	return header + content
}

func readManagedUnit(path string) (unitMeta, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return unitMeta{}, err
	}
	lines := strings.Split(string(data), "\n")
	if len(lines) < 3 || lines[0] != watchpostUnitMarker {
		return unitMeta{}, errNotManaged
	}
	count := 0
	for _, ln := range lines {
		if strings.HasPrefix(ln, watchpostManagedPrefix) {
			count++
		}
	}
	if count != 1 || !strings.HasPrefix(lines[1], watchpostManagedPrefix) {
		return unitMeta{}, errMalformed
	}
	sm := regexp.MustCompile(`^# watchpost-managed: v1 sha256=([0-9a-f]{64})$`).FindStringSubmatch(lines[1])
	if sm == nil {
		return unitMeta{}, errMalformed
	}
	content := strings.Join(lines[2:], "\n")
	sum := sha256.Sum256([]byte(content))
	if hex.EncodeToString(sum[:]) != sm[1] {
		return unitMeta{}, errModified
	}
	meta := unitMeta{}
	listenSeen, dataSeen, envfileSeen, secureSeen, healthSeen := 0, 0, 0, 0, 0
	for _, ln := range lines[2:] {
		switch {
		case strings.HasPrefix(ln, "# watchpost-listen: "):
			listenSeen++
			if listenSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.listen = strings.TrimSpace(strings.TrimPrefix(ln, "# watchpost-listen: "))
		case strings.HasPrefix(ln, "# watchpost-data: "):
			dataSeen++
			if dataSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.data = strings.TrimSpace(strings.TrimPrefix(ln, "# watchpost-data: "))
		case strings.HasPrefix(ln, "# watchpost-envfile: "):
			envfileSeen++
			if envfileSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.envfile = strings.TrimSpace(strings.TrimPrefix(ln, "# watchpost-envfile: "))
		case strings.HasPrefix(ln, "# watchpost-secure-cookies: "):
			secureSeen++
			if secureSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.secure = strings.TrimSpace(strings.TrimPrefix(ln, "# watchpost-secure-cookies: ")) == "1"
		case strings.HasPrefix(ln, "# watchpost-health: "):
			healthSeen++
			if healthSeen > 1 {
				return unitMeta{}, errMalformed
			}
			meta.health = strings.TrimSpace(strings.TrimPrefix(ln, "# watchpost-health: "))
		}
	}
	if listenSeen != 1 || dataSeen != 1 || healthSeen != 1 || meta.listen == "" || meta.data == "" || meta.health == "" {
		return unitMeta{}, errMalformed
	}
	if envfileSeen > 1 || secureSeen > 1 {
		return unitMeta{}, errMalformed
	}
	if meta.health != watchpostHealthPath {
		return unitMeta{}, errMalformed
	}
	for _, v := range []struct{ val, name string }{{meta.listen, "listen"}, {meta.data, "data-dir"}} {
		if err := validateNoControl(v.val, v.name); err != nil {
			return unitMeta{}, errMalformed
		}
	}
	if meta.envfile != "" {
		if err := validateNoControl(meta.envfile, "environment file"); err != nil {
			return unitMeta{}, errMalformed
		}
		if strings.ContainsAny(meta.envfile, "%") {
			return unitMeta{}, errMalformed
		}
	}
	return meta, nil
}

// existingUnitMeta reads a valid managed unit's metadata, or returns an empty
// meta (nil error) when no unit is installed. An existing foreign or modified
// unit is an error so repeated installs never silently diverge from it.
func existingUnitMeta(path string) (unitMeta, error) {
	meta, err := readManagedUnit(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return unitMeta{}, nil
		}
		return unitMeta{}, fmt.Errorf("existing unit at %s is not valid: %w", path, err)
	}
	return meta, nil
}

// resolveInstallValues preserves installed configuration on repeated installs:
// a flag the operator did not explicitly set keeps its existing managed value
// rather than being silently replaced by a CLI default.
func resolveInstallValues(meta unitMeta, visited map[string]bool, listen, dataDir string, secureCookies bool, envfile string) (string, string, bool, string) {
	if !visited["listen"] && meta.listen != "" {
		listen = meta.listen
	}
	if !visited["data-dir"] && meta.data != "" {
		dataDir = meta.data
	}
	if !visited["secure-cookies"] {
		secureCookies = meta.secure
	}
	if !visited["env-file"] && meta.envfile != "" {
		envfile = meta.envfile
	}
	return listen, dataDir, secureCookies, envfile
}

func writeManagedUnit(path, content string) error {
	if _, err := os.Stat(path); err == nil {
		if _, err := readManagedUnit(path); err != nil {
			return fmt.Errorf("refusing to overwrite %s: %w", path, err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".watchpost-unit-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	ok := false
	defer func() {
		if !ok {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.WriteString(content); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(0644); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	ok = true
	return nil
}

func resolveExecutable(exe string) (string, error) {
	if strings.TrimSpace(exe) == "" {
		return "", errors.New("empty executable path")
	}
	if !filepath.IsAbs(exe) {
		return "", fmt.Errorf("executable path %q is not absolute", exe)
	}
	abs := filepath.Clean(exe)
	if strings.HasPrefix(abs, os.TempDir()) {
		return "", fmt.Errorf("executable path %q is transient; install watchpost somewhere stable first", abs)
	}
	if strings.Contains(abs, string(filepath.Separator)+"go-build"+string(filepath.Separator)) {
		return "", fmt.Errorf("executable path %q looks like a Go build cache path", abs)
	}
	if st, err := os.Stat(abs); err != nil || st.IsDir() {
		return "", fmt.Errorf("executable %q is not a file", abs)
	}
	return abs, nil
}

func healthCheck(url string) error {
	client := &http.Client{Timeout: 2 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("expected 2xx, got HTTP %d", resp.StatusCode)
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "json") {
		return fmt.Errorf("expected a JSON response, got %q", resp.Header.Get("Content-Type"))
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var v map[string]any
	if err := json.Unmarshal(body, &v); err != nil {
		return fmt.Errorf("expected a JSON object response: %v", err)
	}
	return nil
}

func (m *serviceManager) requireManaged(verb string) error {
	if _, err := readManagedUnit(m.unitPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("refusing to %s %s: unit is not installed", verb, m.unitName)
		}
		return fmt.Errorf("refusing to %s %s: %w", verb, m.unitName, err)
	}
	return nil
}

// revalidateEnv checks the currently recorded environment file again so a file
// deleted or made unsafe since install cannot silently change the service's
// configuration. Stop, logs and uninstall intentionally skip this so operators
// are never trapped with an unmanageable service.
func (m *serviceManager) revalidateEnv(meta unitMeta) error {
	if meta.envfile == "" {
		return nil
	}
	if err := validateEnvFile(meta.envfile); err != nil {
		return fmt.Errorf("the recorded environment file is no longer valid: %w", err)
	}
	return nil
}

func (m *serviceManager) install(listen, dataDir string, secureCookies bool, envfile string, out io.Writer) error {
	for _, v := range []struct{ val, name string }{
		{listen, "listen"}, {dataDir, "data-dir"},
	} {
		if err := validateNoControl(v.val, v.name); err != nil {
			return err
		}
	}
	if err := validateReadWritePath(dataDir); err != nil {
		return err
	}
	if err := prepareDataDir(dataDir); err != nil {
		return err
	}
	if envfile != "" {
		if err := validateEnvFile(envfile); err != nil {
			return err
		}
	}
	// Snapshot the prior managed state so a failed install can restore both the
	// unit file and the systemd enabled/active state.
	priorUnit, hadUnit := readFileIfPresent(m.unitPath)
	priorEnabled := stateNotEnabled
	priorActive := stateInactive
	if hadUnit {
		if _, err := readManagedUnit(m.unitPath); err != nil {
			return fmt.Errorf("refusing to overwrite the existing unit: %w", err)
		}
		var err error
		priorEnabled, err = m.queryState("is-enabled")
		if err != nil {
			return fmt.Errorf("cannot determine the prior enablement state: %w", err)
		}
		priorActive, err = m.queryState("is-active")
		if err != nil {
			return fmt.Errorf("cannot determine the prior service state: %w", err)
		}
	}
	unit := buildWatchpostUnit(m.exe, listen, dataDir, secureCookies, envfile)
	if err := writeManagedUnit(m.unitPath, unit); err != nil {
		return err
	}
	// Restart (not start) so a changed listener, data directory, secure-cookies
	// flag or environment file takes effect on an already-running service.
	for _, step := range []struct {
		verb string
		args []string
	}{
		{"reloading systemd", []string{"daemon-reload"}},
		{"enabling", []string{"enable", m.unitName}},
		{"restarting", []string{"restart", m.unitName}},
	} {
		if err := m.systemctlSuccess(step.args...); err != nil {
			if rb := m.rollbackInstall(priorUnit, hadUnit, priorEnabled, priorActive); rb != "" {
				return fmt.Errorf("%s %s failed: %w%s", step.verb, m.unitName, err, rb)
			}
			return fmt.Errorf("%s %s failed: %w", step.verb, m.unitName, err)
		}
	}
	active, _, _ := m.systemctl("is-active", m.unitName)
	fmt.Fprintf(out, "unit:   %s\n", m.unitName)
	fmt.Fprintf(out, "file:   %s\n", m.unitPath)
	fmt.Fprintf(out, "state:  %s\n", strings.TrimSpace(active))
	fmt.Fprintf(out, "url:    http://%s\n", listen)
	return nil
}

func readFileIfPresent(path string) ([]byte, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	return data, true
}

func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".watchpost-restore-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

// systemctlTolerantMissing runs a systemctl verb treating "unit not loaded /
// not found" results as success, which is expected when rolling back a failed
// fresh install whose unit has already been removed.
func (m *serviceManager) systemctlTolerantMissing(args ...string) error {
	out, code, err := m.systemctl(args...)
	if err != nil {
		low := strings.ToLower(err.Error())
		if strings.Contains(low, "not loaded") || strings.Contains(low, "not found") || strings.Contains(low, "no such file") {
			return nil
		}
		return err
	}
	if code != 0 {
		low := strings.ToLower(out)
		if strings.Contains(low, "not loaded") || strings.Contains(low, "not found") || strings.Contains(low, "no such file") {
			return nil
		}
		return fmt.Errorf("systemctl %s exited %d: %s", strings.Join(args, " "), code, bounded(strings.TrimSpace(out)))
	}
	return nil
}

// rollbackInstall restores the prior unit and systemd enabled/active state after
// a failed install, removing the new unit for a fresh install. It returns an
// explanatory string when rollback itself fails so callers never claim a full
// rollback when only the files were restored.
func (m *serviceManager) rollbackInstall(priorUnit []byte, hadUnit bool, priorEnabled, priorActive svcState) string {
	var errs []string
	if hadUnit {
		if err := writeFileAtomic(m.unitPath, priorUnit, 0644); err != nil {
			errs = append(errs, fmt.Sprintf("restore unit: %v", err))
		}
	} else if err := os.Remove(m.unitPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		errs = append(errs, fmt.Sprintf("remove new unit: %v", err))
	}
	if err := m.systemctlSuccess("daemon-reload"); err != nil {
		errs = append(errs, fmt.Sprintf("reload systemd: %v", err))
	}
	if priorEnabled == stateEnabled {
		if err := m.systemctlSuccess("enable", m.unitName); err != nil {
			errs = append(errs, fmt.Sprintf("restore enabled: %v", err))
		}
	} else if err := m.systemctlTolerantMissing("disable", m.unitName); err != nil {
		errs = append(errs, fmt.Sprintf("restore disabled: %v", err))
	}
	if priorActive == stateActive {
		if err := m.systemctlSuccess("restart", m.unitName); err != nil {
			errs = append(errs, fmt.Sprintf("restore active: %v", err))
		}
	} else if err := m.systemctlTolerantMissing("stop", m.unitName); err != nil {
		errs = append(errs, fmt.Sprintf("restore inactive: %v", err))
	}
	if len(errs) > 0 {
		return "; rollback incomplete: " + strings.Join(errs, "; ")
	}
	return ""
}

func (m *serviceManager) action(verb string, out io.Writer) error {
	if err := m.requireManaged(verb); err != nil {
		return err
	}
	if verb == "start" || verb == "restart" {
		meta, err := readManagedUnit(m.unitPath)
		if err != nil {
			return err
		}
		if err := m.revalidateEnv(meta); err != nil {
			return fmt.Errorf("refusing to %s %s: %w", verb, m.unitName, err)
		}
	}
	o, code, err := m.systemctl(verb, m.unitName)
	if out != nil && strings.TrimSpace(o) != "" {
		fmt.Fprintln(out, strings.TrimSpace(o))
	}
	if err != nil {
		return fmt.Errorf("cannot run systemctl %s %s: %w", verb, m.unitName, err)
	}
	if code != 0 {
		return fmt.Errorf("systemctl %s %s exited %d: %s", verb, m.unitName, code, bounded(strings.TrimSpace(o)))
	}
	return nil
}

func (m *serviceManager) status(out io.Writer, version string) error {
	meta, err := readManagedUnit(m.unitPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s is not installed (no unit at %s)", m.unitName, m.unitPath)
		}
		return fmt.Errorf("%s unit is not valid: %w", m.unitName, err)
	}
	enabled, err := m.queryState("is-enabled")
	if err != nil {
		return fmt.Errorf("cannot determine %s enablement state: %w", m.unitName, err)
	}
	if err := m.revalidateEnv(meta); err != nil {
		return fmt.Errorf("cannot report status: %w", err)
	}
	active, err := m.queryState("is-active")
	if err != nil {
		return fmt.Errorf("cannot determine %s service state: %w", m.unitName, err)
	}
	pid, _, _ := m.systemctl("show", "-p", "MainPID", "--value", m.unitName)
	fmt.Fprintf(out, "unit:    %s\n", m.unitName)
	fmt.Fprintf(out, "file:    %s\n", m.unitPath)
	fmt.Fprintf(out, "enabled: %s\n", enabled)
	fmt.Fprintf(out, "active:  %s\n", active)
	fmt.Fprintf(out, "pid:     %s\n", strings.TrimSpace(pid))
	fmt.Fprintf(out, "version: %s\n", version)
	fmt.Fprintf(out, "listen:  %s\n", meta.listen)
	fmt.Fprintf(out, "data:    %s\n", meta.data)
	if meta.envfile != "" {
		fmt.Fprintf(out, "env:     %s\n", meta.envfile)
	}
	if active != stateActive {
		return fmt.Errorf("%s is %q; expected active", m.unitName, active)
	}
	if err := healthCheck("http://" + meta.listen + meta.health); err != nil {
		fmt.Fprintf(out, "health:  unreachable (%v)\n", err)
		return fmt.Errorf("service is active but its health check failed: %v", err)
	}
	fmt.Fprintln(out, "health:  ok")
	return nil
}

func (m *serviceManager) logs(follow bool, out io.Writer) error {
	if err := m.requireManaged("view logs for"); err != nil {
		return err
	}
	args := []string{"--user-unit", m.unitName}
	if follow {
		args = append(args, "-f")
		code, err := m.run.Stream("journalctl", args...)
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("journalctl exited with status %d", code)
		}
		return nil
	}
	o, code, err := m.run.Run("journalctl", args...)
	if err != nil {
		return fmt.Errorf("cannot run journalctl: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("journalctl exited %d: %s", code, bounded(strings.TrimSpace(o)))
	}
	fmt.Fprint(out, o)
	return nil
}

func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		_ = f.Sync()
		_ = f.Close()
	}
}

var (
	linkFile = os.Link
	removeFile = os.Remove
	randomSuffix = func() (string, error) {
		b := make([]byte, 8)
		if _, err := rand.Read(b); err != nil {
			return "", err
		}
		return hex.EncodeToString(b), nil
	}
)

// backupManagedUnit moves the managed unit aside to a unique hidden backup name
// in the same directory. It uses an exclusive hard link so an existing retained
// backup is never overwritten; the original is unlinked only after the backup
// link exists, and on any failure the original stays intact with no backup
// artifact left behind.
func backupManagedUnit(path string) (string, error) {
	dir := filepath.Dir(path)
	for i := 0; i < 32; i++ {
		suffix, err := randomSuffix()
		if err != nil {
			return "", fmt.Errorf("cannot generate a backup name: %w", err)
		}
		backup := filepath.Join(dir, "."+filepath.Base(path)+".unit-backup-"+suffix)
		if err := linkFile(path, backup); err != nil {
			if errors.Is(err, os.ErrExist) {
				continue // candidate already exists; try another name
			}
			return "", err
		}
		if err := removeFile(path); err != nil {
			_ = os.Remove(backup)
			return "", fmt.Errorf("cannot remove the original after backing it up: %w", err)
		}
		syncDir(dir)
		return backup, nil
	}
	return "", errors.New("could not allocate a unique backup name")
}

func restoreFromBackup(orig, backup string) error {
	if err := os.Link(backup, orig); err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("refusing to overwrite a concurrently created unit at %s; the original unit is preserved at %s", orig, backup)
		}
		return err
	}
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	syncDir(filepath.Dir(orig))
	return nil
}

func (m *serviceManager) uninstall(out io.Writer) error {
	if _, err := readManagedUnit(m.unitPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%s is not installed", m.unitName)
		}
		return fmt.Errorf("refusing to uninstall %s: %w", m.unitName, err)
	}
	active, err := m.queryState("is-active")
	if err != nil {
		return fmt.Errorf("cannot determine %s state before uninstall: %w", m.unitName, err)
	}
	if active == stateActive || active == stateReloading || active == stateRefreshing || active == stateTransition {
		if err := m.systemctlSuccess("stop", m.unitName); err != nil {
			return fmt.Errorf("stop %s failed: %w", m.unitName, err)
		}
		after, err := m.queryState("is-active")
		if err != nil {
			return fmt.Errorf("cannot verify %s stopped after stop: %w", m.unitName, err)
		}
		if after != stateInactive {
			return fmt.Errorf("%s still reports %q after stop; not removing the unit", m.unitName, stateName(after))
		}
	} else if active == stateInactive {
		fmt.Fprintf(out, "note: %s is inactive; nothing to stop\n", m.unitName)
	} else {
		return fmt.Errorf("%s is in %q; cannot confirm it is safely stopped before uninstall", m.unitName, stateName(active))
	}
	enabled, err := m.queryState("is-enabled")
	if err != nil {
		return fmt.Errorf("cannot determine %s enablement before uninstall: %w", m.unitName, err)
	}
	if enabled == stateEnabled {
		if err := m.systemctlSuccess("disable", m.unitName); err != nil {
			return fmt.Errorf("disable %s failed: %w", m.unitName, err)
		}
		after, err := m.queryState("is-enabled")
		if err != nil {
			return fmt.Errorf("cannot verify %s disabled after disable: %w", m.unitName, err)
		}
		if after != stateNotEnabled && after != stateMasked {
			return fmt.Errorf("%s still reports %q after disable; not removing the unit", m.unitName, stateName(after))
		}
	} else if enabled == stateNotEnabled || enabled == stateMasked {
		fmt.Fprintf(out, "note: %s is %s; nothing to disable\n", m.unitName, stateName(enabled))
	} else {
		return fmt.Errorf("%s enablement is %q; cannot confirm it is disabled before uninstall", m.unitName, stateName(enabled))
	}
	backup, err := backupManagedUnit(m.unitPath)
	if err != nil {
		return fmt.Errorf("cannot move %s aside for uninstall: %w", m.unitName, err)
	}
	if err := m.systemctlSuccess("daemon-reload"); err != nil {
		if restoreErr := restoreFromBackup(m.unitPath, backup); restoreErr != nil {
			return fmt.Errorf("reloading systemd after removing %s: %w; additionally failed to restore the unit: %v", m.unitName, err, restoreErr)
		}
		if reloadErr := m.systemctlSuccess("daemon-reload"); reloadErr != nil {
			return fmt.Errorf("reloading systemd after removing %s: %w; the managed unit was restored but the follow-up reload also failed: %v", m.unitName, err, reloadErr)
		}
		return fmt.Errorf("reloading systemd after removing %s: %w; the managed unit was restored", m.unitName, err)
	}
	if err := os.Remove(backup); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	syncDir(filepath.Dir(m.unitPath))
	fmt.Fprintf(out, "Removed %s. Watchpost data and configuration were preserved.\n", m.unitName)
	return nil
}

func runService(args []string, version string) int {
	cmd := "status"
	rest := args
	for i, a := range args {
		if a != "" && !strings.HasPrefix(a, "-") {
			cmd = a
			rest = append(append([]string{}, args[:i]...), args[i+1:]...)
			break
		}
	}
	fs := flag.NewFlagSet("watchpost service "+cmd, flag.ContinueOnError)
	system := fs.Bool("system", false, "install a system-wide unit (not yet supported; user mode is the default)")
	follow := fs.Bool("follow", false, "follow new journal output")
	listen := fs.String("listen", "127.0.0.1:8080", "listen address recorded in the unit")
	dataDir := fs.String("data-dir", "", "data directory recorded in the unit (default from WATCHPOST_DATA_DIR or user config)")
	secureCookies := fs.Bool("secure-cookies", false, "mark session cookies Secure behind an HTTPS reverse proxy")
	envFile := fs.String("env-file", "", "absolute owner-only environment file for WATCHPOST_* variables")
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if *system {
		fmt.Fprintln(os.Stderr, "watchpost: system-wide service mode is not yet supported; use user mode (default) or the foreground command")
		return 2
	}
	if runtime.GOOS != "linux" {
		fmt.Fprintln(os.Stderr, "watchpost: service installation requires Linux systemd")
		return 2
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		fmt.Fprintln(os.Stderr, "watchpost: systemctl not found; is systemd installed?")
		return 1
	}
	m := &serviceManager{
		unitName: "watchpost.service",
		unitPath: userUnitPath("watchpost.service"),
		run:      execRunner{},
	}
	visited := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { visited[f.Name] = true })
	meta, err := existingUnitMeta(m.unitPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "watchpost:", err)
		return 1
	}
	*listen, *dataDir, *secureCookies, *envFile = resolveInstallValues(meta, visited, *listen, *dataDir, *secureCookies, *envFile)
	if *dataDir == "" {
		if v := os.Getenv("WATCHPOST_DATA_DIR"); v != "" {
			*dataDir = v
		} else if dir, aerr := os.UserConfigDir(); aerr == nil {
			*dataDir = filepath.Join(dir, "watchpost")
		}
	}
	if !filepath.IsAbs(*dataDir) {
		fmt.Fprintln(os.Stderr, "watchpost: --data-dir must be an absolute path")
		return 2
	}
	switch cmd {
	case "install":
		exe, err := os.Executable()
		if err != nil {
			fmt.Fprintln(os.Stderr, "watchpost:", err)
			return 1
		}
		exe, err = resolveExecutable(exe)
		if err != nil {
			fmt.Fprintln(os.Stderr, "watchpost:", err)
			return 1
		}
		m.exe = exe
		if err := m.install(*listen, *dataDir, *secureCookies, *envFile, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost:", err)
			return 1
		}
		return 0
	case "start", "stop", "restart":
		if err := m.action(cmd, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost:", err)
			return 1
		}
		return 0
	case "status":
		if err := m.status(os.Stdout, version); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost:", err)
			return 1
		}
		return 0
	case "logs":
		if err := m.logs(*follow, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost:", err)
			return 1
		}
		return 0
	case "uninstall":
		if err := m.uninstall(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost:", err)
			return 1
		}
		return 0
	default:
		fmt.Fprintf(os.Stderr, "watchpost: unknown service command %q\n\nUsage: watchpost service <install|start|stop|restart|status|logs|uninstall> [flags]\n", cmd)
		return 2
	}
}