package service

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newStrictService returns a setup whose fake runner fails on any unconfigured
// systemd invocation, so an unexpected enable/start/stop/restart can never be
// hidden by a permissive default success.
func newStrictService(t *testing.T) *fakeRunner {
	t.Helper()
	r := setupService(t)
	r.strict = true
	return r
}

// installChangedUnit drives a reinstall that is guaranteed to change the unit
// (different listen) and therefore reach the mutation/activation path.
func installChangedUnit(t *testing.T, r *fakeRunner, listen string) error {
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	return Install(exe, "/var/lib/watchpost", listen, false, "")
}

// stateMatrixEntry is a table row proving either exact restoration (accepted)
// or refusal before mutation (rejected).
type stateMatrixEntry struct {
	name          string
	enabled       string
	active        string
	accepted      bool
	wantEnableSeq []string // expected enable restore sequence when accepted
	wantActive    string   // restart or stop
}

func TestInstallStateMatrix(t *testing.T) {
	matrix := []stateMatrixEntry{
		{name: "enabled+active", enabled: "enabled", active: "active", accepted: true, wantEnableSeq: []string{"systemctl enable watchpost.service"}, wantActive: "restart"},
		{name: "enabled+inactive", enabled: "enabled", active: "inactive", accepted: true, wantEnableSeq: []string{"systemctl enable watchpost.service"}, wantActive: "stop"},
		{name: "enabled-runtime+active", enabled: "enabled-runtime", active: "active", accepted: true, wantEnableSeq: []string{"systemctl enable --runtime watchpost.service"}, wantActive: "restart"},
		{name: "enabled-runtime+inactive", enabled: "enabled-runtime", active: "inactive", accepted: true, wantEnableSeq: []string{"systemctl enable --runtime watchpost.service"}, wantActive: "stop"},
		{name: "disabled+active", enabled: "disabled", active: "active", accepted: true, wantEnableSeq: []string{}, wantActive: "restart"},
		{name: "disabled+inactive", enabled: "disabled", active: "inactive", accepted: true, wantEnableSeq: []string{}, wantActive: "stop"},
		// Rejected states must be refused before any mutation.
		{name: "masked+active", enabled: "masked", active: "active", accepted: false},
		{name: "masked-runtime+inactive", enabled: "masked-runtime", active: "inactive", accepted: false},
		{name: "static+inactive", enabled: "static", active: "inactive", accepted: false},
		{name: "linked+inactive", enabled: "linked", active: "inactive", accepted: false},
		{name: "generated+inactive", enabled: "generated", active: "inactive", accepted: false},
		{name: "transient+inactive", enabled: "transient", active: "inactive", accepted: false},
		{name: "failed+inactive", enabled: "failed", active: "inactive", accepted: false},
		{name: "enabled+reloading", enabled: "enabled", active: "reloading", accepted: false},
		{name: "enabled+activating", enabled: "enabled", active: "activating", accepted: false},
	}
	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			r := newStrictService(t)
			installManagedUnit(t)
			setState(r, tc.enabled, tc.active)
			exe := filepath.Join(t.TempDir(), "wp")
			os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
			if tc.accepted {
				// The reinstall changes the listen, so the forward path runs.
				// Force a rollback state-independently: the forward daemon-reload
				// fails (1st call), the rollback daemon-reload succeeds (2nd call).
				r.seq["systemctl daemon-reload"] = []fakeResult{{out: "reload failed", code: 1}, {}}
				r.script["systemctl enable watchpost.service"] = fakeResult{}
				r.script["systemctl enable --runtime watchpost.service"] = fakeResult{}
				r.script["systemctl restart watchpost.service"] = fakeResult{}
				r.script["systemctl stop watchpost.service"] = fakeResult{}
				r.script["systemctl disable watchpost.service"] = fakeResult{}
				if e := Install(exe, "/var/lib/watchpost", "127.0.0.1:9090", false, ""); e == nil {
					t.Fatalf("install with activation failure should return an error")
				}
				// Rollback must reproduce the exact prior enablement and active
				// state: the enable restore sequence and the activation verb.
				for _, want := range tc.wantEnableSeq {
					if !contains(r.log, want) {
						t.Fatalf("rollback did not restore enablement %q: log=%v", tc.enabled, r.log)
					}
				}
				if tc.wantEnableSeq == nil {
					if contains(r.log, "systemctl enable --runtime watchpost.service") || contains(r.log, "systemctl enable watchpost.service") {
						t.Fatalf("disabled prior should not be re-enabled: log=%v", r.log)
					}
				}
				if tc.wantActive == "restart" && !contains(r.log, "systemctl restart watchpost.service") {
					t.Fatalf("active prior not restarted on rollback: log=%v", r.log)
				}
				if tc.wantActive == "stop" && !contains(r.log, "systemctl stop watchpost.service") {
					t.Fatalf("inactive prior not stopped on rollback: log=%v", r.log)
				}
				// The prior unit must be restored.
				b, _ := os.ReadFile(UnitPath)
				if !strings.Contains(string(b), "127.0.0.1:8080") {
					t.Fatalf("prior unit not restored: log=%v", r.log)
				}
			} else {
				// Rejected: Install must refuse BEFORE mutating the binary or unit.
				beforeBin, _ := os.ReadFile(BinaryPath)
				if e := Install(exe, "/var/lib/watchpost", "127.0.0.1:9090", false, ""); e == nil {
					t.Fatalf("install of non-restorable state %s succeeded", tc.name)
				}
				afterBin, _ := os.ReadFile(BinaryPath)
				if !bytes.Equal(beforeBin, afterBin) {
					t.Fatalf("rejected state %s still mutated the binary", tc.name)
				}
				for _, call := range r.log {
					if strings.HasPrefix(call, "systemctl enable ") || strings.HasPrefix(call, "systemctl disable ") ||
						strings.HasPrefix(call, "systemctl start ") || strings.HasPrefix(call, "systemctl stop ") ||
						strings.HasPrefix(call, "systemctl restart ") || call == "systemctl daemon-reload" {
						t.Fatalf("rejected state %s mutated lifecycle before refusal: %s", tc.name, call)
					}
				}
			}
		})
	}
}

func TestSuccessfulReinstallPreservesPriorState(t *testing.T) {
	// A successful changed reinstall must preserve the exact prior enablement
	// and activity states, NOT convert every service to enabled+active. This
	// exercises the real forward Install() path (no induced failure).
	matrix := []stateMatrixEntry{
		{name: "enabled+active", enabled: "enabled", active: "active", wantEnableSeq: []string{"systemctl enable watchpost.service"}, wantActive: "restart"},
		{name: "enabled+inactive", enabled: "enabled", active: "inactive", wantEnableSeq: []string{"systemctl enable watchpost.service"}, wantActive: "stop"},
		{name: "enabled-runtime+active", enabled: "enabled-runtime", active: "active", wantEnableSeq: []string{"systemctl enable --runtime watchpost.service"}, wantActive: "restart"},
		{name: "enabled-runtime+inactive", enabled: "enabled-runtime", active: "inactive", wantEnableSeq: []string{"systemctl enable --runtime watchpost.service"}, wantActive: "stop"},
		{name: "disabled+active", enabled: "disabled", active: "active", wantEnableSeq: []string{}, wantActive: "restart"},
		{name: "disabled+inactive", enabled: "disabled", active: "inactive", wantEnableSeq: []string{}, wantActive: "stop"},
	}
	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			r := newStrictService(t)
			installManagedUnit(t)
			setState(r, tc.enabled, tc.active)
			exe := filepath.Join(t.TempDir(), "wp2")
			os.WriteFile(exe, []byte("#!/bin/sh\n# changed binary\nexit 0\n"), 0o755)
			// Script the full forward path; it must SUCCEED (no induced failure).
			r.script["systemctl daemon-reload"] = fakeResult{}
			r.script["systemctl enable watchpost.service"] = fakeResult{}
			r.script["systemctl enable --runtime watchpost.service"] = fakeResult{}
			r.script["systemctl disable watchpost.service"] = fakeResult{}
			r.script["systemctl restart watchpost.service"] = fakeResult{}
			r.script["systemctl stop watchpost.service"] = fakeResult{}
			// The listen changes so the unit changes (a real changed reinstall).
			if e := Install(exe, "/var/lib/watchpost", "127.0.0.1:9090", false, ""); e != nil {
				t.Fatalf("successful reinstall failed: %v", e)
			}
			// The forward path must reproduce the exact prior enablement: the
			// runtime-only prior must NOT be converted to a persistent enable.
			for _, want := range tc.wantEnableSeq {
				if !contains(r.log, want) {
					t.Fatalf("reinstall did not apply enablement %q: log=%v", tc.enabled, r.log)
				}
			}
			if tc.enabled == "enabled-runtime" {
				if contains(r.log, "systemctl enable watchpost.service") {
					t.Fatalf("enabled-runtime prior was converted to persistent enable: log=%v", r.log)
				}
			}
			if tc.enabled == "disabled" {
				if contains(r.log, "systemctl enable watchpost.service") || contains(r.log, "systemctl enable --runtime watchpost.service") {
					t.Fatalf("disabled prior was enabled by reinstall: log=%v", r.log)
				}
			}
			// The forward path must reproduce the exact prior activity.
			if tc.wantActive == "restart" && !contains(r.log, "systemctl restart watchpost.service") {
				t.Fatalf("active prior not restarted on successful reinstall: log=%v", r.log)
			}
			if tc.wantActive == "stop" && !contains(r.log, "systemctl stop watchpost.service") {
				t.Fatalf("inactive prior not stopped on successful reinstall: log=%v", r.log)
			}
		})
	}
}

func TestFreshInstallEstablishesDefaultState(t *testing.T) {
	// A fresh install (no existing unit) establishes enabled + active.
	r := newStrictService(t)
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost.service"] = fakeResult{}
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	if e := Install(exe, "/var/lib/watchpost", "127.0.0.1:8080", false, ""); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "systemctl enable watchpost.service") {
		t.Fatal("fresh install did not enable the service")
	}
	if !contains(r.log, "systemctl restart watchpost.service") {
		t.Fatal("fresh install did not start the service")
	}
}

func TestInstallStateQueryFailureAborts(t *testing.T) {
	r := newStrictService(t)
	installManagedUnit(t)
	beforeBin, _ := os.ReadFile(BinaryPath)
	r.script["systemctl is-enabled watchpost.service"] = fakeResult{out: "", code: 1, err: fmt.Errorf("is-enabled failed")}
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := Install(exe, "/var/lib/watchpost", "127.0.0.1:9090", false, ""); e == nil {
		t.Fatal("install proceeded despite is-enabled query failure")
	}
	afterBin, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(beforeBin, afterBin) {
		t.Fatal("state-query failure still mutated the binary")
	}
}

func TestInstallRollbackSurfacesRecoveryFailure(t *testing.T) {
	r := newStrictService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	// Forward: daemon-reload succeeds (1st), enable succeeds, restart fails.
	// Rollback: daemon-reload is the 2nd call and fails -> rollback incomplete.
	r.seq["systemctl daemon-reload"] = []fakeResult{{}, {out: "reload failed", code: 1}}
	r.script["systemctl enable watchpost.service"] = fakeResult{out: "failed to enable", code: 1}
	r.script["systemctl restart watchpost.service"] = fakeResult{out: "activation failed", code: 1}
	r.script["systemctl stop watchpost.service"] = fakeResult{}
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	e := Install(exe, "/var/lib/watchpost", "127.0.0.1:9090", false, "")
	if e == nil {
		t.Fatal("install succeeded despite activation failure")
	}
	if !strings.Contains(e.Error(), "rollback incomplete") {
		t.Fatalf("install did not surface the rollback failure: %v", e)
	}
	if !strings.Contains(e.Error(), "reload systemd") {
		t.Fatalf("install did not surface the rollback root cause: %v", e)
	}
}

func TestEnvFileRequiresRootOwnership(t *testing.T) {
	setupService(t)
	dir := t.TempDir()
	env := filepath.Join(dir, "watchpost.env")
	os.WriteFile(env, []byte("WATCHPOST_MASTER_KEY=x\n"), 0o600)
	// Root-owned (uid 0) is accepted.
	oldUID := fileUID
	fileUID = func(os.FileInfo) int { return 0 }
	defer func() { fileUID = oldUID }()
	if e := validateEnvFile(env); e != nil {
		t.Fatalf("root-owned 0600 env file rejected: %v", e)
	}
	// Service-user-owned (uid 4242) is rejected.
	fileUID = func(os.FileInfo) int { return 4242 }
	if e := validateEnvFile(env); e == nil {
		t.Fatal("service-user-owned 0600 env file accepted")
	} else if !strings.Contains(e.Error(), "root") {
		t.Fatalf("owner rejection lacks root diagnostic: %v", e)
	}
	// Root-owned but 0640 is rejected.
	os.Chmod(env, 0o640)
	fileUID = func(os.FileInfo) int { return 0 }
	if e := validateEnvFile(env); e == nil {
		t.Fatal("root-owned 0640 env file accepted")
	}
	os.Chmod(env, 0o600)
	// A symlink is rejected.
	link := filepath.Join(dir, "link.env")
	if e := os.Symlink(env, link); e != nil {
		t.Fatal(e)
	}
	fileUID = func(os.FileInfo) int { return 0 }
	if e := validateEnvFile(link); e == nil {
		t.Fatal("symlink env file accepted")
	}
	// A non-regular file (directory) is rejected.
	dir2 := filepath.Join(dir, "subdir")
	os.MkdirAll(dir2, 0o700)
	if e := validateEnvFile(dir2); e == nil {
		t.Fatal("directory env file accepted")
	}
}

func TestDataDirRejectsSystemRoots(t *testing.T) {
	r := newStrictService(t)
	for _, root := range []string{"/", "/etc", "/usr", "/var", "/bin", "/home"} {
		exe := filepath.Join(t.TempDir(), "wp")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		if e := Install(exe, root, "127.0.0.1:8080", false, ""); e == nil {
			t.Fatalf("install accepted system data directory %q", root)
		}
		if len(r.log) != 0 {
			t.Fatalf("install of %q touched systemctl", root)
		}
	}
}

func TestDataDirRefusesUnrelatedExistingDirectory(t *testing.T) {
	r := newStrictService(t)
	useRealDataDirSeams(t)
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing-data")
	os.MkdirAll(existing, 0o755)
	marker := filepath.Join(existing, "sentinel")
	os.WriteFile(marker, []byte("keep"), 0o644)
	// The service account UID differs from the directory's real owner (the test
	// user), so the descriptor-relative inspection must refuse adoption.
	serviceUID = func() (int, error) { return os.Getuid() + 10000, nil }
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := Install(exe, existing, "127.0.0.1:8080", false, ""); e == nil {
		t.Fatal("install adopted an unrelated existing directory")
	}
	// The dangerous directory must remain byte-for-byte/metadata unchanged.
	if b, e := os.ReadFile(marker); e != nil || string(b) != "keep" {
		t.Fatalf("existing directory content mutated: %q %v", b, e)
	}
	info, _ := os.Lstat(existing)
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("existing directory mode mutated to %v", info.Mode().Perm())
	}
	if len(r.log) != 0 {
		t.Fatalf("rejected existing directory still ran systemctl: %v", r.log)
	}
}

func TestDataDirLeafOnlyCreation(t *testing.T) {
	r := newStrictService(t)
	useRealDataDirSeams(t)
	// The parent must already exist; only the final leaf is created.
	parent := t.TempDir()
	newData := filepath.Join(parent, "watchpost-data")
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost.service"] = fakeResult{}
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	if e := Install(exe, newData, "127.0.0.1:8080", false, ""); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(newData); e != nil {
		t.Fatalf("leaf was not actually created: %v", e)
	}
	if entries, _ := os.ReadDir(parent); len(entries) != 1 {
		t.Fatalf("parent gained unexpected entries: %v", entries)
	}
}

func TestDataDirRefusesMissingParent(t *testing.T) {
	r := newStrictService(t)
	useRealDataDirSeams(t)
	dir := t.TempDir()
	missingParent := filepath.Join(dir, "does-not-exist")
	dataDir := filepath.Join(missingParent, "watchpost-data")
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := Install(exe, dataDir, "127.0.0.1:8080", false, ""); e == nil {
		t.Fatal("install created a data directory under a missing parent")
	}
	if _, e := os.Lstat(missingParent); !os.IsNotExist(e) {
		t.Fatalf("missing parent %q was created by the installer", missingParent)
	}
	if len(r.log) != 0 {
		t.Fatalf("missing-parent install still ran systemctl: %v", r.log)
	}
}

func TestDataDirRejectsUnderSystemTree(t *testing.T) {
	r := newStrictService(t)
	for _, root := range []string{"/etc/watchpost-data", "/usr/local/watchpost", "/bin/watchpost"} {
		exe := filepath.Join(t.TempDir(), "wp")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		if e := Install(exe, root, "127.0.0.1:8080", false, ""); e == nil {
			t.Fatalf("install accepted data directory %q beneath a system tree", root)
		}
		if len(r.log) != 0 {
			t.Fatalf("install of %q touched systemctl", root)
		}
	}
	// The canonical /var/lib and /srv locations are accepted (under /var and
	// /srv, which are not protected trees).
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := validateDataDirPath("/var/lib/watchpost"); e != nil {
		t.Fatalf("canonical /var/lib/watchpost rejected: %v", e)
	}
	if e := validateDataDirPath("/srv/watchpost"); e != nil {
		t.Fatalf("canonical /srv/watchpost rejected: %v", e)
	}
}

func TestRecoveryTimeMarkerProvesTiming(t *testing.T) {
	r := newStrictService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", false)
	healthWindow = 1
	exe := filepath.Join(t.TempDir(), "wp2")
	newBin := []byte("#!/bin/sh\n# v2\nexit 0\n")
	os.WriteFile(exe, newBin, 0o755)
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	r.script["systemctl stop watchpost.service"] = fakeResult{}
	var seamSaw struct {
		markerWritten bool
		binaryIsNew   bool
		logLenAtSeam  int
	}
	orig := priorStateFileRead
	priorStateFileRead = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, ".prior-active") {
			// At the instant recovery reads the marker, Update() must have
			// written it, the installed binary must be the new one, and recovery
			// must not yet have issued its own stop/restart (the log still only
			// contains the update's single restart plus state queries).
			if _, e := os.Stat(BinaryPath + ".prior-active"); e == nil {
				seamSaw.markerWritten = true
			}
			cur, _ := os.ReadFile(BinaryPath)
			seamSaw.binaryIsNew = bytes.Equal(cur, newBin)
			seamSaw.logLenAtSeam = len(r.log)
			stopCount, restartCount := 0, 0
			for _, c := range r.log {
				if c == "systemctl stop watchpost.service" {
					stopCount++
				}
				if c == "systemctl restart watchpost.service" {
					restartCount++
				}
			}
			if stopCount != 0 {
				t.Fatalf("recovery issued stop before reading the marker (log=%v)", r.log)
			}
			if restartCount != 1 {
				t.Fatalf("expected exactly the update's restart before recovery marker read, got %d (log=%v)", restartCount, r.log)
			}
			return nil, fmt.Errorf("marker vanished at recovery time")
		}
		return os.ReadFile(path)
	}
	defer func() { priorStateFileRead = orig }()
	uerr := Update(exe, fakeSHA(exe))
	if uerr == nil {
		t.Fatal("update succeeded despite recovery marker failure")
	}
	if !seamSaw.markerWritten {
		t.Fatal("recovery seam fired but Update never wrote the marker; test is not exercising recovery-time")
	}
	if !seamSaw.binaryIsNew {
		t.Fatal("recovery seam fired but the installed binary is not the new one; timing wrong")
	}
	if seamSaw.logLenAtSeam == 0 {
		t.Fatal("recovery seam did not record a log position")
	}
	if !strings.Contains(uerr.Error(), "recovery") {
		t.Fatalf("recovery fail-closed not surfaced: %v", uerr)
	}
	// After the failed marker read, recovery must NOT have issued any further
	// lifecycle verb beyond what existed at the seam (the update's restart).
	for _, c := range r.log[seamSaw.logLenAtSeam:] {
		if strings.HasPrefix(c, "systemctl ") {
			t.Fatalf("recovery issued a lifecycle verb after the failed marker read: %s", c)
		}
	}
}

// mutationCounters records whether any mutating operation was invoked, so a
// refusal can prove zero account/mkdir/chmod/chown mutation.
type mutationCounters struct {
	account bool
	mkdir   bool
	chmod   bool
	chown   bool
}

func watchMutations(t *testing.T) *mutationCounters {
	t.Helper()
	c := &mutationCounters{}
	oldAccount, oldMkdir, oldChmod, oldChown := ensureAccount, mkdirAtLeafSeam, fchmodLeafSeam, fchownLeafSeam
	ensureAccount = func() error { c.account = true; return nil }
	mkdirAtLeafSeam = func(int, string) error { c.mkdir = true; return nil }
	fchmodLeafSeam = func(int) error { c.chmod = true; return nil }
	fchownLeafSeam = func(int) error { c.chown = true; return nil }
	t.Cleanup(func() {
		ensureAccount, mkdirAtLeafSeam, fchmodLeafSeam, fchownLeafSeam = oldAccount, oldMkdir, oldChmod, oldChown
	})
	return c
}

func (c *mutationCounters) any() bool {
	return c.account || c.mkdir || c.chmod || c.chown
}

// useRealDataDirSeams switches the descriptor-relative data-dir seams to their
// real syscall implementations so a test exercises the actual filesystem
// establishment (creation, chmod, chown, unlink relative to a directory fd).
func useRealDataDirSeams(t *testing.T) {
	t.Helper()
	openDataParentSeam = openDataParentReal
	dataParentConsistentSeam = dataParentConsistentReal
	statDataLeafSeam = statDataLeafReal
	mkdirAtLeafSeam = mkdirAtLeafReal
	openAtLeafSeam = openAtLeafReal
	fchmodLeafSeam = fchmodLeafReal
	fchownLeafSeam = func(fd int) error { return nil } // tests run unprivileged; ownership is simulated
	fstatLeafSeam = fstatLeafReal
	unlinkAtSeam = unlinkAtLeafReal
	closeFdSeam = closeFdReal
}

// hasMutatingSystemctl reports whether the fake runner issued a mutating
// lifecycle verb (enable/disable/start/stop/restart/daemon-reload).
func hasMutatingSystemctl(log []string) bool {
	for _, call := range log {
		for _, prefix := range []string{
			"systemctl enable ", "systemctl disable ", "systemctl start ",
			"systemctl restart ", "systemctl stop ", "systemctl daemon-reload",
		} {
			if strings.HasPrefix(call, prefix) {
				return true
			}
		}
	}
	return false
}

// TestInstallRefusalCausesZeroMutation proves every preflight refusal occurs
// before any account, mkdir, chmod, chown, binary, unit or lifecycle mutation.
func TestInstallRefusalCausesZeroMutation(t *testing.T) {
	refusalCases := []struct {
		name  string
		setup func(t *testing.T, r *fakeRunner) // returns after arranging the failure
	}{
		{
			name: "foreign-unit",
			setup: func(t *testing.T, r *fakeRunner) {
				writeFileAtomic(UnitPath, []byte("[Unit]\nDescription=admin\n[Service]\nExecStart=/usr/bin/x\n[Install]\nWantedBy=multi-user.target\n"), 0o644)
			},
		},
		{
			name: "tampered-unit",
			setup: func(t *testing.T, r *fakeRunner) {
				installManagedUnit(t)
				u := string(mustRead(t, UnitPath))
				writeFileAtomic(UnitPath, []byte(strings.Replace(u, "127.0.0.1:8080", "127.0.0.1:9999", 1)), 0o644)
			},
		},
		{
			name: "unsupported-enabled-state",
			setup: func(t *testing.T, r *fakeRunner) {
				installManagedUnit(t)
				setState(r, "masked", "inactive")
			},
		},
		{
			name: "unsupported-active-state",
			setup: func(t *testing.T, r *fakeRunner) {
				installManagedUnit(t)
				setState(r, "enabled", "reloading")
			},
		},
		{
			name: "state-query-failure",
			setup: func(t *testing.T, r *fakeRunner) {
				installManagedUnit(t)
				r.script["systemctl is-enabled watchpost.service"] = fakeResult{out: "", code: 1, err: fmt.Errorf("query failed")}
			},
		},
		{
			name: "invalid-incoming-executable",
			setup: func(t *testing.T, r *fakeRunner) {
				installManagedUnit(t)
				setState(r, "enabled", "inactive")
			},
		},
		{
			name: "invalid-env-file",
			setup: func(t *testing.T, r *fakeRunner) {
				installManagedUnit(t)
				setState(r, "enabled", "inactive")
			},
		},
		{
			name: "unacceptable-data-dir",
			setup: func(t *testing.T, r *fakeRunner) {
				installManagedUnit(t)
				setState(r, "enabled", "inactive")
				// An existing leaf not owned by the service account is refused
				// during preflight inspection (descriptor-relative stat).
				statDataLeafSeam = func(int, string) (dataLeafInfo, error) {
					return dataLeafInfo{isDir: true, mode: 0o755, uid: 1000}, nil
				}
			},
		},
	}
	for _, tc := range refusalCases {
		t.Run(tc.name, func(t *testing.T) {
			r := newStrictService(t)
			c := watchMutations(t)
			tc.setup(t, r)
			exe := filepath.Join(t.TempDir(), "wp")
			os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
			dataDir := "/var/lib/watchpost"
			envfile := ""
			badEnv := false
			if tc.name == "invalid-incoming-executable" {
				os.Remove(exe)
			}
			if tc.name == "invalid-env-file" {
				envfile = filepath.Join(t.TempDir(), "bad.env")
				os.WriteFile(envfile, []byte("X=1\n"), 0o644) // not 0600
				badEnv = true
			}
			beforeBin, _ := os.ReadFile(BinaryPath)
			e := Install(exe, dataDir, "127.0.0.1:9090", false, envfile)
			_ = badEnv
			if e == nil {
				t.Fatalf("refusal case %s unexpectedly succeeded", tc.name)
			}
			if c.any() {
				t.Fatalf("refusal case %s performed account/mkdir/chmod/chown mutation: %+v", tc.name, c)
			}
			afterBin, _ := os.ReadFile(BinaryPath)
			if !bytes.Equal(beforeBin, afterBin) {
				t.Fatalf("refusal case %s mutated the binary", tc.name)
			}
			// Read-only state queries (is-enabled/is-active) are non-mutating
			// and permitted; any mutating lifecycle verb is a violation.
			for _, call := range r.log {
				if strings.HasPrefix(call, "systemctl enable ") || strings.HasPrefix(call, "systemctl disable ") ||
					strings.HasPrefix(call, "systemctl start ") || strings.HasPrefix(call, "systemctl stop ") ||
					strings.HasPrefix(call, "systemctl restart ") || call == "systemctl daemon-reload" {
					t.Fatalf("refusal case %s performed a lifecycle mutation: %s", tc.name, call)
				}
			}
		})
	}
}

func TestDataDirRefusesAncestorSymlinkEscape(t *testing.T) {
	r := newStrictService(t)
	useRealDataDirSeams(t)
	base := t.TempDir()
	protected := filepath.Join(base, "protected")
	os.MkdirAll(protected, 0o755)
	// /base/link -> protected; a lexical /base/link/project would resolve into
	// the protected target if the ancestor symlink were followed.
	link := filepath.Join(base, "link")
	if e := os.Symlink(protected, link); e != nil {
		t.Fatal(e)
	}
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	dataDir := filepath.Join(link, "project")
	if e := Install(exe, dataDir, "127.0.0.1:8080", false, ""); e == nil {
		t.Fatal("install followed an ancestor symlink escape")
	}
	// No leaf is created at the resolved target.
	if _, e := os.Lstat(filepath.Join(protected, "project")); !os.IsNotExist(e) {
		t.Fatalf("leaf created at resolved protected target: %v", e)
	}
	if _, e := os.Lstat(dataDir); !os.IsNotExist(e) {
		t.Fatalf("leaf created through the symlink: %v", e)
	}
	if len(r.log) != 0 {
		t.Fatalf("ancestor-symlink install touched systemctl: %v", r.log)
	}
}

func TestDataDirChmodFailureOnNewLeaf(t *testing.T) {
	r := newStrictService(t)
	useRealDataDirSeams(t)
	parent := t.TempDir()
	newData := filepath.Join(parent, "wp-data")
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	fchmodLeafSeam = func(int) error { return fmt.Errorf("chmod failed") }
	if e := Install(exe, newData, "127.0.0.1:8080", false, ""); e == nil {
		t.Fatal("install succeeded despite data-dir chmod failure")
	} else if !strings.Contains(e.Error(), "0700") {
		t.Fatalf("chmod failure not surfaced: %v", e)
	}
	// The partial freshly-created leaf must have been cleaned up via the
	// retained parent descriptor.
	if _, e := os.Lstat(newData); !os.IsNotExist(e) {
		t.Fatalf("partial leaf left behind after chmod failure: %v", e)
	}
	if len(r.log) != 0 {
		t.Fatalf("chmod-failure install touched systemctl: %v", r.log)
	}
}

func TestDataDirChmodFailureOnExistingLeaf(t *testing.T) {
	r := newStrictService(t)
	useRealDataDirSeams(t)
	dir := t.TempDir()
	existing := filepath.Join(dir, "wp-data")
	os.MkdirAll(existing, 0o755)
	fchmodLeafSeam = func(int) error { return fmt.Errorf("chmod failed") }
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := Install(exe, existing, "127.0.0.1:8080", false, ""); e == nil {
		t.Fatal("install succeeded despite existing data-dir chmod failure")
	} else if !strings.Contains(e.Error(), "0700") {
		t.Fatalf("existing-leaf chmod failure not surfaced: %v", e)
	}
	if len(r.log) != 0 {
		t.Fatalf("existing-leaf chmod-failure install touched systemctl: %v", r.log)
	}
}

func TestInstallRollbackSurfacesNeutralizationFailures(t *testing.T) {
	// Forward failure + rollback stop failure.
	{
		r := newStrictService(t)
		installManagedUnit(t)
		setState(r, "enabled", "active")
		exe := filepath.Join(t.TempDir(), "wp")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		r.script["systemctl daemon-reload"] = fakeResult{}
		r.script["systemctl disable watchpost.service"] = fakeResult{}
		r.script["systemctl enable watchpost.service"] = fakeResult{}
		// Forward restart fails; rollback neutralization stop also fails.
		r.script["systemctl restart watchpost.service"] = fakeResult{out: "activation failed", code: 1}
		r.script["systemctl stop watchpost.service"] = fakeResult{out: "cannot stop", code: 1}
		e := Install(exe, "/var/lib/watchpost", "127.0.0.1:9090", false, "")
		if e == nil {
			t.Fatal("install succeeded despite forward failure")
		}
		if !strings.Contains(e.Error(), "neutralize stop") {
			t.Fatalf("rollback stop failure not surfaced: %v", e)
		}
		if !strings.Contains(e.Error(), "rollback incomplete") {
			t.Fatalf("rollback incomplete not reported: %v", e)
		}
	}
	// Forward failure + rollback disable failure.
	{
		r := newStrictService(t)
		installManagedUnit(t)
		setState(r, "enabled", "inactive")
		exe := filepath.Join(t.TempDir(), "wp")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		r.script["systemctl daemon-reload"] = fakeResult{}
		r.script["systemctl disable watchpost.service"] = fakeResult{out: "cannot disable", code: 1}
		r.script["systemctl enable watchpost.service"] = fakeResult{}
		r.script["systemctl stop watchpost.service"] = fakeResult{}
		e := Install(exe, "/var/lib/watchpost", "127.0.0.1:9090", false, "")
		if e == nil {
			t.Fatal("install succeeded despite forward failure")
		}
		if !strings.Contains(e.Error(), "neutralize disable") {
			t.Fatalf("rollback disable failure not surfaced: %v", e)
		}
	}
}

// TestUnchangedReinstallPreservesPriorState proves an UNCHANGED existing
// reinstall (identical unit and binary, present-safe service-owned data leaf)
// is a genuine no-op: no enable/disable/start/stop/restart/daemon-reload is
// issued, so the exact prior state (disabled+inactive, enabled-runtime, etc.)
// is preserved by doing nothing.
func TestUnchangedReinstallPreservesPriorState(t *testing.T) {
	matrix := []stateMatrixEntry{
		{name: "enabled+active", enabled: "enabled", active: "active"},
		{name: "enabled+inactive", enabled: "enabled", active: "inactive"},
		{name: "enabled-runtime+active", enabled: "enabled-runtime", active: "active"},
		{name: "enabled-runtime+inactive", enabled: "enabled-runtime", active: "inactive"},
		{name: "disabled+active", enabled: "disabled", active: "active"},
		{name: "disabled+inactive", enabled: "disabled", active: "inactive"},
	}
	for _, tc := range matrix {
		t.Run(tc.name, func(t *testing.T) {
			r := newStrictService(t)
			useRealDataDirSeams(t)
			dataDir := filepath.Join(t.TempDir(), "wp-data")
			if e := os.Mkdir(dataDir, 0o700); e != nil {
				t.Fatal(e)
			}
			serviceUID = func() (int, error) { return os.Getuid(), nil }
			writeFileAtomic(UnitPath, []byte(Unit(dataDir, "127.0.0.1:8080", false, "")), 0o644)
			setState(r, tc.enabled, tc.active)
			exe := filepath.Join(t.TempDir(), "wp2")
			os.WriteFile(exe, mustRead(t, BinaryPath), 0o755)
			if e := Install(exe, dataDir, "127.0.0.1:8080", false, ""); e != nil {
				t.Fatalf("unchanged reinstall failed: %v", e)
			}
			for _, call := range r.log {
				if strings.HasPrefix(call, "systemctl enable ") || strings.HasPrefix(call, "systemctl disable ") ||
					strings.HasPrefix(call, "systemctl start ") || strings.HasPrefix(call, "systemctl stop ") ||
					strings.HasPrefix(call, "systemctl restart ") || call == "systemctl daemon-reload" {
					t.Fatalf("unchanged %s reinstall performed a lifecycle mutation: %s", tc.name, call)
				}
			}
		})
	}
}

// TestNoOpRepairsMissingDataLeaf proves a safely missing data leaf is repaired
// (established) even when unit/binary are identical and state is preserved,
// rather than being reported as already-correct.
func TestNoOpRepairsMissingDataLeaf(t *testing.T) {
	r := newStrictService(t)
	useRealDataDirSeams(t)
	// The data leaf does not exist; the parent (temp dir) does.
	dataDir := filepath.Join(t.TempDir(), "wp-data")
	// Install a managed unit that matches the data dir so the unit is identical.
	if e := writeFileAtomic(UnitPath, []byte(Unit(dataDir, "127.0.0.1:8080", false, "")), 0o644); e != nil {
		t.Fatal(e)
	}
	setState(r, "enabled", "active")
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, mustRead(t, BinaryPath), 0o755)
	if e := Install(exe, dataDir, "127.0.0.1:8080", false, ""); e != nil {
		t.Fatalf("repair install failed: %v", e)
	}
	if _, e := os.Lstat(dataDir); e != nil {
		t.Fatalf("repaired leaf not created: %v", e)
	}
	// The unit/binary are identical and state preserved, so no lifecycle
	// mutation should have occurred (read-only state queries are permitted).
	for _, call := range r.log {
		if strings.HasPrefix(call, "systemctl enable ") || strings.HasPrefix(call, "systemctl disable ") ||
			strings.HasPrefix(call, "systemctl start ") || strings.HasPrefix(call, "systemctl stop ") ||
			strings.HasPrefix(call, "systemctl restart ") || call == "systemctl daemon-reload" {
			t.Fatalf("repair install performed a lifecycle mutation: %s", call)
		}
	}
}

// TestDataDirEstablishmentFailuresCleanUp proves a failure to fully establish
// the data leaf (chown, bind, or post-creation inspection) fails the install
// before any binary/unit/systemd mutation, removes the partial leaf via the
// retained parent descriptor, and reports the cleanup result.
func TestDataDirEstablishmentFailuresCleanUp(t *testing.T) {
	run := func(name string, breakIt func()) {
		t.Run(name, func(t *testing.T) {
			r := newStrictService(t)
			useRealDataDirSeams(t)
			leaf := filepath.Join(t.TempDir(), "webfleet")
			binBefore := mustRead(t, BinaryPath)
			breakIt()
			exe := filepath.Join(t.TempDir(), "wp")
			os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
			if e := Install(exe, leaf, "127.0.0.1:8080", false, ""); e == nil {
				t.Fatal("install succeeded despite a data-leaf establishment failure")
			}
			if _, e := os.Stat(UnitPath); !os.IsNotExist(e) {
				t.Fatal("unit written despite the data-leaf failure")
			}
			if got := mustRead(t, BinaryPath); !bytes.Equal(got, binBefore) {
				t.Fatal("binary mutated despite the data-leaf failure")
			}
			if hasMutatingSystemctl(r.log) {
				t.Fatalf("systemctl mutated despite the data-leaf failure: %v", r.log)
			}
			if _, e := os.Stat(leaf); !os.IsNotExist(e) {
				t.Fatal("partial leaf was not cleaned up after the establishment failure")
			}
		})
	}
	run("chown-failure", func() { fchownLeafSeam = func(int) error { return errors.New("chown denied") } })
	run("bind-failure", func() {
		openAtLeafSeam = func(int, string) (int, error) { return -1, errors.New("bind denied") }
	})
	run("inspection-failure", func() {
		fstatLeafSeam = func(int) (dataLeafInfo, error) { return dataLeafInfo{}, errors.New("inspect denied") }
	})

	// A cleanup failure after a failed establishment must be reported, not
	// silently claimed as rolled back.
	t.Run("cleanup-failure-reported", func(t *testing.T) {
		r := newStrictService(t)
		useRealDataDirSeams(t)
		leaf := filepath.Join(t.TempDir(), "webfleet")
		fchmodLeafSeam = func(int) error { return errors.New("chmod denied") }
		unlinkAtSeam = func(int, string) error { return errors.New("unlink denied") }
		exe := filepath.Join(t.TempDir(), "wp")
		os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
		if e := Install(exe, leaf, "127.0.0.1:8080", false, ""); e == nil {
			t.Fatal("install succeeded despite a cleanup failure")
		} else if !strings.Contains(e.Error(), "partial leaf cleanup incomplete") {
			t.Fatalf("cleanup failure not surfaced: %v", e)
		}
		if len(r.log) != 0 {
			t.Fatal("cleanup-failure install touched systemctl")
		}
	})
}

// TestDataDirAncestorSwapAfterInspectionRefused proves an ancestor replaced
// after inspection (before leaf creation) is detected via the retained parent
// descriptor and refused; the substituted location never receives a leaf.
func TestDataDirAncestorSwapAfterInspectionRefused(t *testing.T) {
	r := newStrictService(t)
	useRealDataDirSeams(t)
	original := t.TempDir()
	substitute := t.TempDir()
	leaf := filepath.Join(original, "watchpost-data")
	// Between inspection (parent descriptor opened) and establishment, the
	// parent is replaced with a symlink to the substitute. The retained
	// descriptor must cause the establishment to be refused, so neither the
	// substituted target nor the renamed original receives a leaf.
	ensureAccount = func() error {
		if e := os.Rename(original, original+"-moved"); e != nil {
			return e
		}
		return os.Symlink(substitute, original)
	}
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	if e := Install(exe, leaf, "127.0.0.1:8080", false, ""); e == nil {
		t.Fatal("install proceeded after the parent was swapped for a symlink")
	}
	if _, e := os.Stat(filepath.Join(substitute, "watchpost-data")); !os.IsNotExist(e) {
		t.Fatalf("leaf created at the substituted target: %v", e)
	}
	if _, e := os.Stat(filepath.Join(original+"-moved", "watchpost-data")); !os.IsNotExist(e) {
		t.Fatalf("leaf created at the renamed original: %v", e)
	}
	if len(r.log) != 0 {
		t.Fatal("ancestor-swap install touched systemctl")
	}
}
