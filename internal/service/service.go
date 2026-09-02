// Package service implements the machine-service lifecycle for Watchpost:
// a systemd system unit backed by a dedicated unprivileged account, a canonical
// /var/lib/watchpost data directory and root-protected /etc/watchpost
// configuration. The CLI surface, exit-code model and transaction semantics
// mirror the canonical Web Fleet reference so the whole ecosystem behaves
// predictably.
package service

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// UnitPath is the installed systemd system unit.
var UnitPath = "/etc/systemd/system/watchpost.service"

// BinaryPath is the canonical installed binary location.
var BinaryPath = "/usr/local/bin/watchpost"

// DefaultDataDir is the canonical data directory the installed service owns.
const DefaultDataDir = "/var/lib/watchpost"

// DefaultEnvFile is the root-protected environment file holding protected
// WATCHPOST_* configuration (secrets). It is read by systemd via
// EnvironmentFile= before the process drops to User=watchpost.
const DefaultEnvFile = "/etc/watchpost/watchpost.env"

// DefaultListen is the canonical loopback listen address embedded in the unit.
const DefaultListen = "127.0.0.1:8080"

// ServiceAccount is the dedicated unprivileged account the unit runs as.
const ServiceUser = "watchpost"
const ServiceGroup = "watchpost"

// watchpostUnitMarker marks unit files written by `watchpost service`.
const watchpostUnitMarker = "# Managed by watchpost. Do not edit manually."

// watchpostManagedPrefix introduces the versioned integrity header followed by
// a SHA-256 of everything below it, so any hand edit is detected.
const watchpostManagedPrefix = "# watchpost-managed: "

// watchpostHealthPath is the public, read-only liveness endpoint.
const watchpostHealthPath = "/healthz"

var (
	errNotManaged = errors.New("not a managed unit")
	errMalformed  = errors.New("malformed managed unit header")
	errModified   = errors.New("managed unit body no longer matches its recorded checksum")
)

// Runner abstracts systemctl/journalctl so the CLI is testable without a real
// systemd manager. Run returns captured combined output, the exit code (0 on
// success, -1 when the command could not launch) and a launch error only.
type Runner interface {
	Run(name string, args ...string) (string, int, error)
	Stream(name string, args ...string) (int, error)
}

type execRunner struct{}

func (execRunner) Run(name string, args ...string) (string, int, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
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

var defaultRunner Runner = execRunner{}

// setRunner replaces the systemctl runner (test seam; nil restores default).
func setRunner(r Runner) { defaultRunner = r }

func systemctl(args ...string) (string, int, error) { return defaultRunner.Run("systemctl", args...) }

func bounded(s string) string {
	const max = 2000
	if len(s) > max {
		return s[:max] + "..."
	}
	return s
}

func systemctlSuccess(args ...string) error {
	out, code, err := systemctl(args...)
	if err != nil {
		return fmt.Errorf("cannot run systemctl %s: %w", strings.Join(args, " "), err)
	}
	if code != 0 {
		return fmt.Errorf("systemctl %s exited %d: %s", strings.Join(args, " "), code, bounded(strings.TrimSpace(out)))
	}
	return nil
}

// unitStateWord runs a state verb (is-enabled/is-active), tolerating a nonzero
// exit for legitimate negative answers and returning the trimmed word.
func unitStateWord(verb string) (string, error) {
	out, code, err := systemctl(verb, "watchpost.service")
	if err != nil {
		return "", fmt.Errorf("cannot run systemctl %s: %w", verb, err)
	}
	_ = code
	return strings.TrimSpace(out), nil
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

func validateNoControl(v, what string) error {
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] == 0x7f {
			return fmt.Errorf("%s %q contains a control character", what, v)
		}
	}
	return nil
}

func fileSHA256(path string) (string, error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return "", e
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}

// validateManagedUnit performs the structural ownership/integrity check: the
// unit must carry the watchpost managed header AND the required directives, so
// a stale or malformed managed unit is classified rather than treated healthy.
func validateManagedUnit(body []byte) error {
	if _, err := readManagedUnit(string(body)); err != nil {
		return err
	}
	t := string(body)
	for _, want := range []string{"[Unit]", "[Service]", "[Install]", "Description=Watchpost monitoring service", "ExecStart=" + BinaryPath, "User=" + ServiceUser, "WantedBy=multi-user.target"} {
		if !strings.Contains(t, want) {
			return fmt.Errorf("malformed managed unit: missing %q", want)
		}
	}
	return nil
}

// managedUnit reports whether the unit file carries the watchpost marker.
func managedUnit(path string) bool {
	b, e := os.ReadFile(path)
	if e != nil {
		return false
	}
	_, err := readManagedUnit(string(b))
	return err == nil
}

func requireManaged(verb string) error {
	b, e := os.ReadFile(UnitPath)
	if errors.Is(e, os.ErrNotExist) {
		return fmt.Errorf("refusing to %s watchpost.service: unit is not installed (run `watchpost service install`)", verb)
	}
	if e != nil {
		return fmt.Errorf("refusing to %s watchpost.service: %w", verb, e)
	}
	if ve := validateManagedUnit(b); ve != nil {
		return fmt.Errorf("refusing to %s watchpost.service: %v", verb, ve)
	}
	return nil
}

func requireLinux() error {
	if runtime.GOOS != "linux" {
		return errors.New("service management is supported on Linux only")
	}
	return nil
}

var isRoot = func() bool { return os.Geteuid() == 0 }
var ensureAccount = func() error { return ensureServiceAccount() }
var chownData = func(path string) error { return chownService(path) }
var mkdirData = func(path string, mode os.FileMode) error { return os.MkdirAll(path, mode) }

func requireRoot(verb string) error {
	if !isRoot() {
		return fmt.Errorf("%s requires root (sudo watchpost service %s)", verb, verb)
	}
	return nil
}

func copyFile(src, dst string, mode os.FileMode) error {
	in, e := os.Open(src)
	if e != nil {
		return e
	}
	defer in.Close()
	tmp := dst + ".new"
	out, e := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if e != nil {
		return e
	}
	if _, e = io.Copy(out, in); e != nil {
		out.Close()
		return e
	}
	if e = out.Sync(); e != nil {
		out.Close()
		return e
	}
	if e = out.Close(); e != nil {
		return e
	}
	return os.Rename(tmp, dst)
}

// unitMeta carries the recorded managed-unit configuration.
type unitMeta struct {
	listen  string
	data    string
	envfile string
	secure  bool
	health  string
}

// readManagedUnit validates a managed unit's integrity header and parses its
// recorded metadata. Any hand edit is detected via the body checksum.
func readManagedUnit(content string) (unitMeta, error) {
	lines := strings.Split(content, "\n")
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
	contentBody := strings.Join(lines[2:], "\n")
	sum := sha256.Sum256([]byte(contentBody))
	if hex.EncodeToString(sum[:]) != sm[1] {
		return unitMeta{}, errModified
	}
	meta := unitMeta{}
	listenSeen, dataSeen, envfileSeen, secureSeen, healthSeen := 0, 0, 0, 0, 0
	for _, ln := range lines[2:] {
		switch {
		case strings.HasPrefix(ln, "# watchpost-listen: "):
			listenSeen++
			meta.listen = strings.TrimSpace(strings.TrimPrefix(ln, "# watchpost-listen: "))
		case strings.HasPrefix(ln, "# watchpost-data: "):
			dataSeen++
			meta.data = strings.TrimSpace(strings.TrimPrefix(ln, "# watchpost-data: "))
		case strings.HasPrefix(ln, "# watchpost-envfile: "):
			envfileSeen++
			meta.envfile = strings.TrimSpace(strings.TrimPrefix(ln, "# watchpost-envfile: "))
		case strings.HasPrefix(ln, "# watchpost-secure-cookies: "):
			secureSeen++
			meta.secure = strings.TrimSpace(strings.TrimPrefix(ln, "# watchpost-secure-cookies: ")) == "1"
		case strings.HasPrefix(ln, "# watchpost-health: "):
			healthSeen++
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
	return meta, nil
}

// unitBody renders the systemd directives (no managed header).
func unitBody(dataDir, listen string, secureCookies bool, envfile string) string {
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	if listen == "" {
		listen = DefaultListen
	}
	var b strings.Builder
	b.WriteString("[Unit]\n")
	b.WriteString("Description=Watchpost monitoring service\n")
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n\n")
	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	b.WriteString("User=" + ServiceUser + "\n")
	b.WriteString("Group=" + ServiceGroup + "\n")
	b.WriteString("ExecStart=" + BinaryPath)
	b.WriteString(" " + systemdQuote("--listen") + " " + systemdQuote(listen))
	b.WriteString(" " + systemdQuote("--data-dir") + " " + systemdQuote(dataDir))
	if secureCookies {
		b.WriteString(" " + systemdQuote("--secure-cookies"))
	}
	b.WriteString("\n")
	b.WriteString("Restart=on-failure\n")
	b.WriteString("RestartSec=3\n")
	b.WriteString("NoNewPrivileges=true\n")
	b.WriteString("PrivateTmp=true\n")
	b.WriteString("ProtectSystem=strict\n")
	b.WriteString("ProtectHome=true\n")
	b.WriteString("ReadWritePaths=" + systemdQuote(dataDir) + "\n")
	if envfile != "" {
		b.WriteString("EnvironmentFile=" + systemdQuote(envfile) + "\n")
	}
	b.WriteString("\n[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}

// buildUnit returns the full managed unit content.
func buildUnit(dataDir, listen string, secureCookies bool, envfile string) string {
	meta := "# watchpost-listen: " + listen + "\n# watchpost-data: " + dataDir + "\n"
	if secureCookies {
		meta += "# watchpost-secure-cookies: 1\n"
	}
	if envfile != "" {
		meta += "# watchpost-envfile: " + envfile + "\n"
	}
	meta += "# watchpost-health: " + watchpostHealthPath + "\n"
	content := meta + unitBody(dataDir, listen, secureCookies, envfile)
	sum := sha256.Sum256([]byte(content))
	header := watchpostUnitMarker + "\n" + watchpostManagedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n"
	return header + content
}

// Unit returns the full managed unit content (exported for tests).
func Unit(dataDir, listen string, secureCookies bool, envfile string) string {
	return buildUnit(dataDir, listen, secureCookies, envfile)
}

// unitEnv reads an Environment=WEBFLEET_* value from a unit body (none for
// watchpost; metadata lives in the managed header). Provided for parity.
func unitEnv(body, key string) string {
	_ = body
	_ = key
	return ""
}

// writeFileAtomic writes data to path via a temp file + rename.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".watchpost-write-*")
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

// validateEnvFile validates an EnvironmentFile path for the service unit:
// absolute, a regular non-symlink file with exactly owner-only 0600
// permissions, owned by root (uid 0), and free of systemd specifier and
// control characters. Machine configuration is root-owned so the service
// account cannot rewrite its own configuration.
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
	if fileUID(info) != 0 {
		return fmt.Errorf("environment file %q must be owned by root (uid 0); machine configuration is root-owned", path)
	}
	return nil
}

// validateReadWritePath validates a data directory for ReadWritePaths=.
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

// prepareDataDir safely establishes the service data directory. A newly
// created leaf directory is created and assigned to the service account. An
// existing directory is only reused if it is a non-symlink directory already
// owned by the service account with no group/world-write bits; an unrelated
// or root-owned existing directory is refused rather than silently adopted.
func prepareDataDir(path string) error {
	info, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		if e := mkdirData(path, 0o700); e != nil {
			return e
		}
		_ = os.Chmod(path, 0o700)
		if e := chownData(path); e != nil {
			return e
		}
		return nil
	}
	if e != nil {
		return fmt.Errorf("data directory %q: %w", path, e)
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
	if e := requireServiceOwned(path); e != nil {
		return e
	}
	_ = os.Chmod(path, 0o700)
	return nil
}

// Install installs (or idempotently reinstalls) the watchpost systemd unit: it
// creates the service account and data directory, copies the current binary,
// writes the managed unit, daemon-reloads, enables and starts/restarts the
// service. A partial failure restores the prior unit, enablement, active state
// and binary, and the returned error combines the original failure with any
// rollback failure.
func Install(exe, dataDir, listen string, secureCookies bool, envfile string) (retErr error) {
	if e := requireLinux(); e != nil {
		return e
	}
	if !isRoot() {
		return errors.New("service install requires root")
	}
	for _, v := range []struct{ val, name string }{{dataDir, "data dir"}, {listen, "listen"}} {
		if e := validateNoControl(v.val, v.name); e != nil {
			return e
		}
	}
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	if listen == "" {
		listen = DefaultListen
	}
	if e := validateReadWritePath(dataDir); e != nil {
		return e
	}
	if e := validateDataDirPath(dataDir); e != nil {
		return e
	}
	if envfile != "" {
		if e := validateEnvFile(envfile); e != nil {
			return e
		}
	}
	if _, e := exec.LookPath("systemctl"); e != nil {
		return errors.New("systemctl not found; is systemd installed?")
	}
	if e := ensureAccount(); e != nil {
		return e
	}
	if e := prepareDataDir(dataDir); e != nil {
		return e
	}
	unit := buildUnit(dataDir, listen, secureCookies, envfile)
	priorUnit, hadUnit := []byte(nil), false
	if b, e := os.ReadFile(UnitPath); e == nil {
		hadUnit = true
		priorUnit = b
		if ve := validateManagedUnit(b); ve != nil {
			return fmt.Errorf("refusing to reinstall watchpost.service: %v", ve)
		}
	} else if !errors.Is(e, os.ErrNotExist) {
		return e
	}
	// Snapshot and classify the exact prior enablement and active states BEFORE
	// any mutation. Query failures are propagated and every state that cannot
	// be recreated exactly by rollback is refused up front, so install never
	// mutates a state it cannot restore.
	priorEnabled, priorActive := "", ""
	if hadUnit {
		var e error
		if priorEnabled, e = unitStateWord("is-enabled"); e != nil {
			return fmt.Errorf("refusing to reinstall watchpost.service: %w", e)
		}
		if !restorableEnabledWord(priorEnabled) {
			return fmt.Errorf("refusing to reinstall watchpost.service: prior enablement state %q cannot be restored exactly; disable or unmask it first", priorEnabled)
		}
		if priorActive, e = unitStateWord("is-active"); e != nil {
			return fmt.Errorf("refusing to reinstall watchpost.service: %w", e)
		}
		if !restorableActiveWord(priorActive) {
			return fmt.Errorf("refusing to reinstall watchpost.service: prior active state %q cannot be restored exactly; stop or restart it first", priorActive)
		}
		if !restorablePriorState(priorEnabled, priorActive) {
			return fmt.Errorf("refusing to reinstall watchpost.service: prior state %s+%s cannot be restored exactly; unmask it first", priorEnabled, priorActive)
		}
	}
	incomingDigest, err := fileSHA256(exe)
	if err != nil {
		return fmt.Errorf("read incoming executable: %w", err)
	}
	priorBinaryDigest, hadBinary := "", false
	if d, e := fileSHA256(BinaryPath); e == nil {
		hadBinary = true
		priorBinaryDigest = d
	}
	binaryChanged := !hadBinary || incomingDigest != priorBinaryDigest
	if hadUnit && string(priorUnit) == unit && !binaryChanged && priorEnabled == "enabled" && priorActive == "active" {
		return nil
	}
	if hadBinary {
		if e := copyFile(BinaryPath, BinaryPath+".preinstall", 0o755); e != nil {
			return e
		}
	}
	installOK := false
	restore := func() string {
		var errs []string
		_ = systemctlSuccess("stop", "watchpost.service")
		_ = systemctlSuccess("disable", "watchpost.service")
		if hadBinary {
			if e := copyFile(BinaryPath+".preinstall", BinaryPath, 0o755); e != nil {
				errs = append(errs, fmt.Sprintf("restore binary: %v", e))
			}
		} else {
			_ = os.Remove(BinaryPath)
		}
		_ = os.Remove(BinaryPath + ".preinstall")
		if hadUnit {
			if e := writeFileAtomic(UnitPath, priorUnit, 0o644); e != nil {
				errs = append(errs, fmt.Sprintf("restore unit: %v", e))
			}
		} else {
			_ = os.Remove(UnitPath)
		}
		if e := systemctlSuccess("daemon-reload"); e != nil {
			errs = append(errs, fmt.Sprintf("reload systemd: %v", e))
		}
		if hadUnit {
			for _, args := range enableRestoreSteps(priorEnabled, "watchpost.service") {
				if e := systemctlSuccess(args...); e != nil {
					errs = append(errs, fmt.Sprintf("restore enablement %q: %v", priorEnabled, e))
					break
				}
			}
			if e := systemctlSuccess(activeRestoreArgs(priorActive, "watchpost.service")...); e != nil {
				errs = append(errs, fmt.Sprintf("restore active state %q: %v", priorActive, e))
			}
		}
		if len(errs) == 0 {
			return ""
		}
		return "; rollback incomplete: " + strings.Join(errs, "; ")
	}
	defer func() {
		if !installOK && retErr != nil {
			if rb := restore(); rb != "" {
				retErr = fmt.Errorf("%v%s", retErr, rb)
			}
		}
	}()
	if e := copyFile(exe, BinaryPath, 0o755); e != nil {
		return e
	}
	if e := writeFileAtomic(UnitPath, []byte(unit), 0o644); e != nil {
		return e
	}
	unitChanged := !hadUnit || string(priorUnit) != unit
	changed := unitChanged || binaryChanged
	steps := [][]string{{"daemon-reload"}}
	if changed {
		steps = append(steps, []string{"enable", "watchpost.service"}, []string{"restart", "watchpost.service"})
	} else {
		if priorEnabled != "enabled" {
			steps = append(steps, []string{"enable", "watchpost.service"})
		}
		if priorActive != "active" {
			steps = append(steps, []string{"start", "watchpost.service"})
		}
	}
	for _, a := range steps {
		if out, code, err := systemctl(a...); err != nil || code != 0 {
			retErr = fmt.Errorf("systemctl %s: %s: %w (installation rolled back)", strings.Join(a, " "), bounded(strings.TrimSpace(out)), errorIfNil(err, code, a))
			return retErr
		}
	}
	installOK = true
	_ = os.Remove(BinaryPath + ".preinstall")
	return nil
}

// restorableEnabledWord reports whether a prior is-enabled word can be
// recreated exactly by the rollback enablement sequence. Persistent enablement
// (enabled), runtime-only enablement (enabled-runtime) and their absence
// (disabled) are restorable. Masked/static/linked/generated/transient and other
// unit-file states are refused before mutation because enable/disable cannot
// reproduce them.
func restorableEnabledWord(word string) bool {
	switch word {
	case "enabled", "enabled-runtime", "disabled":
		return true
	}
	return false
}

// restorableActiveWord reports whether a prior is-active word can be recreated
// exactly by the rollback activation sequence. Running and stopped are
// restorable; transient, failed, reloading and unknown states are not.
func restorableActiveWord(word string) bool {
	switch word {
	case "active", "inactive":
		return true
	}
	return false
}

// restorablePriorState reports whether the enablement/active pair can be
// reproduced exactly. Only the states restorableEnabledWord and
// restorableActiveWord accept are combined here; this guard exists so any
// future widening of the accept sets must also prove the pair is restorable.
func restorablePriorState(enabledWord, activeWord string) bool {
	return restorableEnabledWord(enabledWord) && restorableActiveWord(activeWord)
}

// enableRestoreSteps returns the systemctl calls that reproduce a prior
// is-enabled word exactly. Enablement is normalized first: the persistent
// enablement link created by the attempted install is removed with disable,
// then the intended persistent or runtime link is recreated, so a runtime-only
// prior never leaves a persistent enablement behind.
func enableRestoreSteps(word, unit string) [][]string {
	switch word {
	case "enabled":
		return [][]string{{"disable", unit}, {"enable", unit}}
	case "enabled-runtime":
		return [][]string{{"disable", unit}, {"enable", "--runtime", unit}}
	default: // disabled
		return [][]string{{"disable", unit}}
	}
}

// activeRestoreArgs returns the systemctl call that reproduces a prior
// is-active word exactly.
func activeRestoreArgs(word, unit string) []string {
	if word == "active" {
		return []string{"restart", unit}
	}
	return []string{"stop", unit}
}

func errorIfNil(err error, code int, args []string) error {
	if err != nil {
		return err
	}
	_ = args
	return fmt.Errorf("exited %d", code)
}

func ensureServiceAccount() error {
	if out, e := exec.Command("groupadd", "--system", ServiceGroup).CombinedOutput(); e != nil {
		if !strings.Contains(string(out), "exists") {
			return fmt.Errorf("groupadd: %s", strings.TrimSpace(string(out)))
		}
	}
	if out, e := exec.Command("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", "--gid", ServiceGroup, ServiceUser).CombinedOutput(); e != nil {
		if !strings.Contains(string(out), "exists") {
			return fmt.Errorf("useradd: %s", strings.TrimSpace(string(out)))
		}
	}
	return nil
}

func chownService(path string) error {
	uid, gid, e := lookupServiceIDs()
	if e != nil {
		return e
	}
	return os.Chown(path, uid, gid)
}

func lookupServiceIDs() (int, int, error) {
	g, e := user.LookupGroup(ServiceGroup)
	if e != nil {
		return 0, 0, fmt.Errorf("service group not found: %w", e)
	}
	gid, _ := strconv.Atoi(g.Gid)
	u, e := user.Lookup(ServiceUser)
	if e != nil {
		return 0, 0, fmt.Errorf("service user not found: %w", e)
	}
	uid, _ := strconv.Atoi(u.Uid)
	return uid, gid, nil
}

// serviceUID returns the numeric UID of the service account. It is a variable
// so tests can simulate the account without a real system user.
var serviceUID = func() (int, error) {
	uid, _, e := lookupServiceIDs()
	return uid, e
}

// systemDataRoots are filesystem and system-prefix directories the service
// installer must never adopt as a data directory. Passing one of these as
// `service install --data` is refused before any mutation.
var systemDataRoots = map[string]bool{
	"/": true, "/bin": true, "/boot": true, "/dev": true, "/etc": true,
	"/home": true, "/lib": true, "/lib64": true, "/opt": true, "/proc": true,
	"/root": true, "/run": true, "/sbin": true, "/srv": true, "/sys": true,
	"/tmp": true, "/usr": true, "/var": true,
}

// validateDataDirPath rejects data-directory paths that are dangerous system
// roots or would require adopting a parent directory. It must run before any
// ownership or mode mutation.
func validateDataDirPath(path string) error {
	clean := filepath.Clean(path)
	if systemDataRoots[clean] {
		return fmt.Errorf("data directory %q is a system directory and cannot be adopted as a service data directory", path)
	}
	return nil
}

// requireServiceOwned validates that an existing data directory is already
// owned by the service account, so the installer never silently adopts an
// unrelated directory. It is a variable so tests can simulate ownership
// without real chown privileges.
var requireServiceOwned = func(path string) error { return requireServiceOwnedReal(path) }

func requireServiceOwnedReal(path string) error {
	info, e := os.Lstat(path)
	if e != nil {
		return e
	}
	uid, e := serviceUID()
	if e != nil {
		return e
	}
	owner := fileUID(info)
	if owner != uid {
		return fmt.Errorf("data directory %q already exists and is owned by UID %d; the %s service requires it to be owned by %s:%s with mode 0700. Move existing data under %s or re-home it; the installer will not adopt an existing directory", path, owner, ServiceUser, ServiceUser, ServiceGroup, DefaultDataDir)
	}
	return nil
}

func lifecycle(verb string) error {
	if e := requireLinux(); e != nil {
		return e
	}
	if e := requireRoot(verb); e != nil {
		return e
	}
	if e := requireManaged(verb); e != nil {
		return e
	}
	if err := systemctlSuccess(verb, "watchpost.service"); err != nil {
		return err
	}
	return nil
}

// Start starts the service.
func Start() error { return lifecycle("start") }

// Stop stops the service.
func Stop() error { return lifecycle("stop") }

// Restart restarts the service.
func Restart() error { return lifecycle("restart") }

// Enable enables the service at boot.
func Enable() error { return lifecycle("enable") }

// Disable disables the service at boot (without stopping it).
func Disable() error { return lifecycle("disable") }

// Uninstall stops and disables the service, removes the unit and reloads
// systemd. The data directory and installed binary are deliberately preserved.
func Uninstall() error {
	if e := requireLinux(); e != nil {
		return e
	}
	if e := requireRoot("uninstall"); e != nil {
		return e
	}
	if e := requireManaged("uninstall"); e != nil {
		return e
	}
	if e := systemctlSuccess("disable", "--now", "watchpost.service"); e != nil {
		return fmt.Errorf("uninstall: %w", e)
	}
	if e := os.Remove(UnitPath); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return systemctlSuccess("daemon-reload")
}

// Status reports the resolved service state, pid, data/listen configuration and
// a live health check. It is read-only and does not require root.
func Status(out io.Writer) error {
	if e := requireLinux(); e != nil {
		return e
	}
	body, e := os.ReadFile(UnitPath)
	if errors.Is(e, os.ErrNotExist) {
		return fmt.Errorf("watchpost.service is not installed (run `watchpost service install`)")
	}
	if e != nil {
		return fmt.Errorf("cannot read %s: %w", UnitPath, e)
	}
	meta, ve := readManagedUnit(string(body))
	if ve != nil {
		return fmt.Errorf("watchpost.service unit at %s is not valid: %v", UnitPath, ve)
	}
	enabled, _ := unitStateWord("is-enabled")
	active, _ := unitStateWord("is-active")
	pid, _, _ := systemctl("show", "-p", "MainPID", "--value", "watchpost.service")
	listen := meta.listen
	dataDir := meta.data
	if listen == "" {
		listen = DefaultListen
	}
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	fmt.Fprintf(out, "unit:    watchpost.service\n")
	fmt.Fprintf(out, "file:    %s\n", UnitPath)
	fmt.Fprintf(out, "enabled: %s\n", strings.TrimSpace(enabled))
	fmt.Fprintf(out, "active:  %s\n", strings.TrimSpace(active))
	fmt.Fprintf(out, "pid:     %s\n", strings.TrimSpace(pid))
	fmt.Fprintf(out, "user:    %s\n", ServiceUser)
	fmt.Fprintf(out, "data:    %s\n", dataDir)
	fmt.Fprintf(out, "listen:  %s\n", listen)
	if meta.envfile != "" {
		fmt.Fprintf(out, "env:     %s\n", meta.envfile)
	}
	if strings.TrimSpace(active) != "active" {
		fmt.Fprintln(out, "health:  not running")
		return fmt.Errorf("watchpost.service is %q; expected active", strings.TrimSpace(active))
	}
	if err := healthCheckFunc("http://" + listen + watchpostHealthPath); err != nil {
		fmt.Fprintf(out, "health:  unreachable (%v)\n", err)
		return fmt.Errorf("service is active but its health check failed: %v", err)
	}
	fmt.Fprintln(out, "health:  ok")
	return nil
}

var healthCheckFunc = func(url string) error { return healthCheckReal(url) }

func healthCheckReal(url string) error {
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("healthz returned %d", resp.StatusCode)
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

// Logs streams the service journal.
func Logs(follow bool, out io.Writer) error {
	if e := requireLinux(); e != nil {
		return e
	}
	if e := requireManaged("view logs for"); e != nil {
		return e
	}
	args := []string{"--unit", "watchpost.service"}
	if follow {
		args = append(args, "-f")
		code, err := defaultRunner.Stream("journalctl", args...)
		if err != nil {
			return err
		}
		if code != 0 {
			return fmt.Errorf("journalctl exited with status %d", code)
		}
		return nil
	}
	o, code, err := defaultRunner.Run("journalctl", args...)
	if err != nil {
		return fmt.Errorf("cannot run journalctl: %w", err)
	}
	if code != 0 {
		return fmt.Errorf("journalctl exited %d: %s", code, bounded(strings.TrimSpace(o)))
	}
	fmt.Fprint(out, o)
	return nil
}

// Verify returns nil when the artifact's SHA-256 matches want.
func Verify(path, want string) error {
	b, e := os.ReadFile(path)
	if e != nil {
		return e
	}
	h := sha256.Sum256(b)
	got := hex.EncodeToString(h[:])
	if !strings.EqualFold(got, strings.TrimSpace(want)) {
		return fmt.Errorf("checksum mismatch: got %s", got)
	}
	return nil
}

// readPriorActiveMarker reads and validates the prior-state marker.
func readPriorActiveMarker() (string, error) {
	b, err := os.ReadFile(BinaryPath + ".prior-active")
	if err != nil {
		return "", err
	}
	priorActive := strings.TrimSpace(string(b))
	if priorActive != "active" && priorActive != "inactive" && priorActive != "dead" && priorActive != "failed" {
		return "", fmt.Errorf("invalid prior-state marker %q", priorActive)
	}
	return priorActive, nil
}

// priorStateFileRead is a narrow injectable seam so tests can corrupt the
// marker at the exact recovery-time stage (after Update has written it).
var priorStateFileRead = os.ReadFile

func Update(artifact, want string) error {
	if e := requireLinux(); e != nil {
		return e
	}
	if !isRoot() {
		return errors.New("update requires root")
	}
	if e := requireManaged("update"); e != nil {
		return e
	}
	if e := Verify(artifact, want); e != nil {
		return e
	}
	priorActive, err := unitStateWord("is-active")
	if err != nil {
		return fmt.Errorf("update: cannot determine current service state: %w", err)
	}
	priorActive = strings.TrimSpace(priorActive)
	if priorActive != "active" && priorActive != "inactive" && priorActive != "dead" && priorActive != "failed" {
		return fmt.Errorf("update: unexpected service state %q; refusing to update", priorActive)
	}
	wasActive := priorActive == "active"
	if _, e := os.Stat(BinaryPath); e == nil {
		if e := copyFile(BinaryPath, BinaryPath+".rollback", 0o755); e != nil {
			return e
		}
		if e := writeFileAtomic(BinaryPath+".prior-active", []byte(priorActive), 0o600); e != nil {
			_ = os.Remove(BinaryPath + ".rollback")
			return fmt.Errorf("update: cannot record rollback state: %w", e)
		}
	}
	if e := copyFile(artifact, BinaryPath, 0o755); e != nil {
		return e
	}
	if !wasActive {
		return nil
	}
	if out, code, err := systemctl("restart", "watchpost.service"); err != nil || code != 0 {
		updateErr := fmt.Errorf("restart after update: %s: %w", bounded(strings.TrimSpace(out)), errorIfNil(err, code, nil))
		return updateFailureWithRecovery(updateErr, restoreAfterFailedUpdate())
	}
	if e := verifyActiveAndHealthy(); e != nil {
		updateErr := fmt.Errorf("update: new binary failed to become healthy: %w", e)
		return updateFailureWithRecovery(updateErr, restoreAfterFailedUpdate())
	}
	return nil
}

var healthWindow = 30 * time.Second

func updateFailureWithRecovery(updateErr, recoveryErr error) error {
	if recoveryErr != nil {
		return fmt.Errorf("%v; recovery also failed: %v", updateErr, recoveryErr)
	}
	return updateErr
}

func verifyActiveAndHealthy() error {
	listen := DefaultListen
	if b, e := os.ReadFile(UnitPath); e == nil {
		if meta, ve := readManagedUnit(string(b)); ve == nil && meta.listen != "" {
			listen = meta.listen
		}
	}
	deadline := time.Now().Add(healthWindow)
	for time.Now().Before(deadline) {
		active, _ := unitStateWord("is-active")
		if strings.TrimSpace(active) == "active" {
			if err := healthCheckFunc("http://" + listen + watchpostHealthPath); err == nil {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("service did not become active and healthy within %s", healthWindow)
}

// restoreAfterFailedUpdate verifiably restores the previous version and its
// operational state after a failed update. It fails closed if the prior-state
// marker is missing or invalid at recovery time.
func restoreAfterFailedUpdate() error {
	b, err := priorStateFileRead(BinaryPath + ".prior-active")
	if err != nil {
		return fmt.Errorf("recovery: no prior-state marker: %w", err)
	}
	priorActive := strings.TrimSpace(string(b))
	if priorActive != "active" && priorActive != "inactive" && priorActive != "dead" && priorActive != "failed" {
		return fmt.Errorf("recovery: invalid prior-state marker %q", priorActive)
	}
	if e := systemctlSuccess("stop", "watchpost.service"); e != nil {
		return fmt.Errorf("recovery: stop failed service: %w", e)
	}
	if e := copyFile(BinaryPath+".rollback", BinaryPath, 0o755); e != nil {
		return fmt.Errorf("recovery: restore old binary: %w", e)
	}
	if priorActive == "active" {
		if e := systemctlSuccess("restart", "watchpost.service"); e != nil {
			return fmt.Errorf("recovery: restart old service: %w", e)
		}
		if e := verifyActiveAndHealthy(); e != nil {
			return fmt.Errorf("recovery: restored service not healthy: %w", e)
		}
	}
	_ = os.Remove(BinaryPath + ".prior-active")
	_ = os.Remove(BinaryPath + ".rollback")
	return nil
}

func Rollback() error {
	if e := requireLinux(); e != nil {
		return e
	}
	if !isRoot() {
		return errors.New("rollback requires root")
	}
	if e := requireManaged("rollback"); e != nil {
		return e
	}
	if _, e := os.Stat(BinaryPath + ".rollback"); e != nil {
		return errors.New("no rollback binary available")
	}
	b, err := priorStateFileRead(BinaryPath + ".prior-active")
	if err != nil {
		return fmt.Errorf("rollback: no prior-state marker; refusing to guess the service state")
	}
	priorActive := strings.TrimSpace(string(b))
	if priorActive != "active" && priorActive != "inactive" && priorActive != "dead" && priorActive != "failed" {
		return fmt.Errorf("rollback: invalid prior-state marker %q", priorActive)
	}
	wasActive := priorActive == "active"
	cur := BinaryPath + ".failed"
	_ = os.Remove(cur)
	if e := os.Rename(BinaryPath, cur); e != nil {
		return e
	}
	if e := os.Rename(BinaryPath+".rollback", BinaryPath); e != nil {
		_ = os.Rename(cur, BinaryPath)
		return e
	}
	if !wasActive {
		_ = os.Remove(BinaryPath + ".prior-active")
		_ = os.Remove(BinaryPath + ".rollback")
		return nil
	}
	if e := systemctlSuccess("restart", "watchpost.service"); e != nil {
		return e
	}
	if e := verifyActiveAndHealthy(); e != nil {
		return e
	}
	_ = os.Remove(BinaryPath + ".prior-active")
	_ = os.Remove(BinaryPath + ".rollback")
	return nil
}

// Executable returns the absolute path of the running binary.
func Executable() string { p, _ := os.Executable(); p, _ = filepath.Abs(p); return p }
