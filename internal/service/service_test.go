package service

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeResult struct {
	out  string
	code int
	err  error
}

type fakeRunner struct {
	script map[string]fakeResult
	log    []string
	calls  map[string]int
	seq    map[string][]fakeResult
	// strict makes any unconfigured systemctl/journalctl invocation fail with
	// a nonzero exit so an unexpected lifecycle call can never be hidden by a
	// permissive default success.
	strict bool
}

func (f *fakeRunner) Run(name string, args ...string) (string, int, error) {
	key := name + " " + strings.Join(args, " ")
	f.log = append(f.log, key)
	if f.calls == nil {
		f.calls = map[string]int{}
	}
	n := f.calls[key]
	f.calls[key] = n + 1
	if seq, ok := f.seq[key]; ok && n < len(seq) {
		r := seq[n]
		return r.out, r.code, r.err
	}
	if r, ok := f.script[key]; ok {
		return r.out, r.code, r.err
	}
	if f.strict {
		return "", 1, fmt.Errorf("unexpected command: %s", key)
	}
	return "", 0, nil
}

func (f *fakeRunner) Stream(name string, args ...string) (int, error) {
	key := name + " " + strings.Join(args, " ")
	f.log = append(f.log, key)
	if r, ok := f.script[key]; ok {
		return r.code, r.err
	}
	if f.strict {
		return 1, fmt.Errorf("unexpected command: %s", key)
	}
	return 0, nil
}

func setupService(t *testing.T) *fakeRunner {
	t.Helper()
	dir := t.TempDir()
	oldUnit, oldBin := UnitPath, BinaryPath
	oldRoot, oldAccount := isRoot, ensureAccount
	oldUID := serviceUID
	oldOpenParent, oldConsistent := openDataParentSeam, dataParentConsistentSeam
	oldParentSafe := parentSafeSeam
	oldStatLeaf, oldMkdirAt := statDataLeafSeam, mkdirAtLeafSeam
	oldOpenAt, oldChmod, oldChown := openAtLeafSeam, fchmodLeafSeam, fchownLeafSeam
	oldFstat, oldUnlink, oldClose := fstatLeafSeam, unlinkAtSeam, closeFdSeam
	oldRunner := defaultRunner
	oldHealth := healthWindow
	oldPriorRead := priorStateFileRead
	UnitPath = filepath.Join(dir, "watchpost.service")
	BinaryPath = filepath.Join(dir, "watchpost")
	os.WriteFile(BinaryPath, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	isRoot = func() bool { return true }
	ensureAccount = func() error { return nil }
	serviceUID = func() (int, error) { return 4242, nil }
	openDataParentSeam = func(string) (int, error) { return 1, nil }
	dataParentConsistentSeam = func(int, string) bool { return true }
	parentSafeSeam = func(int) error { return nil }
	statDataLeafSeam = func(int, string) (dataLeafInfo, error) { return dataLeafInfo{}, os.ErrNotExist }
	mkdirAtLeafSeam = func(int, string) error { return nil }
	openAtLeafSeam = func(int, string) (int, error) { return 2, nil }
	fchmodLeafSeam = func(int) error { return nil }
	fchownLeafSeam = func(int) error { return nil }
	fstatLeafSeam = func(int) (dataLeafInfo, error) {
		return dataLeafInfo{isDir: true, mode: 0o700, uid: 4242}, nil
	}
	unlinkAtSeam = func(int, string) error { return nil }
	closeFdSeam = func(int) error { return nil }
	r := &fakeRunner{script: map[string]fakeResult{}, seq: map[string][]fakeResult{}}
	r.script["systemctl reset-failed watchpost.service"] = fakeResult{}
	defaultRunner = r
	t.Cleanup(func() {
		UnitPath, BinaryPath = oldUnit, oldBin
		isRoot, ensureAccount = oldRoot, oldAccount
		serviceUID = oldUID
		openDataParentSeam, dataParentConsistentSeam = oldOpenParent, oldConsistent
		parentSafeSeam = oldParentSafe
		statDataLeafSeam, mkdirAtLeafSeam = oldStatLeaf, oldMkdirAt
		openAtLeafSeam, fchmodLeafSeam, fchownLeafSeam = oldOpenAt, oldChmod, oldChown
		fstatLeafSeam, unlinkAtSeam, closeFdSeam = oldFstat, oldUnlink, oldClose
		healthWindow = oldHealth
		priorStateFileRead = oldPriorRead
		healthCheckFunc = func(url string) error { return healthCheckReal(url) }
		defaultRunner = oldRunner
	})
	return r
}

func installManagedUnit(t *testing.T) {
	t.Helper()
	if e := writeFileAtomic(UnitPath, []byte(Unit(DefaultDataDir, "127.0.0.1:8080", false, "")), 0o644); e != nil {
		t.Fatal(e)
	}
}

func setState(r *fakeRunner, enabled, active string) {
	r.script["systemctl is-enabled watchpost.service"] = fakeResult{out: enabled, code: 0}
	r.script["systemctl is-active watchpost.service"] = fakeResult{out: active, code: 0}
}

func prepareUpdate(r *fakeRunner, active string, healthOK bool) {
	r.script["systemctl is-active watchpost.service"] = fakeResult{out: active, code: 0}
	old := healthCheckFunc
	healthCheckFunc = func(url string) error {
		if !healthOK {
			return fmt.Errorf("health failed")
		}
		return nil
	}
	_ = old
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	return b
}

func fakeSHA(path string) string {
	h, _ := fileSHA256(path)
	return h
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func TestUnitHardeningAndManagedMarker(t *testing.T) {
	setupService(t)
	u := Unit(DefaultDataDir, "127.0.0.1:8080", false, "")
	for _, x := range []string{"# Managed by watchpost. Do not edit manually.", "NoNewPrivileges=true", "ProtectSystem=strict", "ReadWritePaths=\"/var/lib/watchpost\"", "User=" + ServiceUser, "Group=" + ServiceGroup, "WantedBy=multi-user.target"} {
		if !strings.Contains(u, x) {
			t.Fatal("missing " + x)
		}
	}
	if !strings.Contains(Unit("/var/lib/watchpost", "127.0.0.1:8080", false, "/etc/watchpost/watchpost.env"), "EnvironmentFile=\"/etc/watchpost/watchpost.env\"") {
		t.Fatal("env file not referenced")
	}
	if e := writeFileAtomic(UnitPath, []byte(u), 0o644); e != nil {
		t.Fatal(e)
	}
	if !managedUnit(UnitPath) {
		t.Fatal("managed marker not detected")
	}
}

func TestValidateNoControlAndQuote(t *testing.T) {
	if e := validateNoControl("127.0.0.1:8080", "listen"); e != nil {
		t.Fatal(e)
	}
	if e := validateNoControl("127.0.0.1:8080\nfoo", "listen"); e == nil {
		t.Fatal("newline accepted")
	}
	if got := systemdQuote(`/a b/"x"$y`); got != `"/a b/\"x\"\$y"` {
		t.Fatalf("quote = %q", got)
	}
}

func TestLifecycleVerbsRequireManagedUnit(t *testing.T) {
	r := setupService(t)
	for _, v := range []string{"start", "stop", "restart", "enable", "disable"} {
		if err := lifecycle(v); err == nil {
			t.Fatalf("%s succeeded without an installed unit", v)
		}
		if len(r.log) != 0 {
			t.Fatalf("%s touched systemctl without a managed unit", v)
		}
	}
	installManagedUnit(t)
	r.script["systemctl start watchpost.service"] = fakeResult{}
	if err := lifecycle("start"); err != nil {
		t.Fatal(err)
	}
	if !contains(r.log, "systemctl start watchpost.service") {
		t.Fatal("start did not call systemctl")
	}
	r.script["systemctl stop watchpost.service"] = fakeResult{out: "Job failed", code: 1}
	if err := lifecycle("stop"); err == nil {
		t.Fatal("failed stop returned nil")
	}
}

func TestLifecycleRefusesForeignUnit(t *testing.T) {
	setupService(t)
	if e := writeFileAtomic(UnitPath, []byte("[Unit]\nDescription=admin unit\n"), 0o644); e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"start", "stop", "restart", "enable", "disable", "uninstall"} {
		if err := lifecycle(v); err == nil {
			t.Fatalf("%s modified a foreign unit", v)
		}
	}
}

func TestInstallRequiresRoot(t *testing.T) {
	oldRoot := isRoot
	isRoot = func() bool { return false }
	defer func() { isRoot = oldRoot }()
	if e := Install("", t.TempDir(), "127.0.0.1:0", false, ""); e == nil {
		t.Fatal("install succeeded without root")
	}
}

func TestReinstallRestoresPriorUnitOnFailure(t *testing.T) {
	r := setupService(t)
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost.service"] = fakeResult{}
	r.script["systemctl start watchpost.service"] = fakeResult{}
	if e := Install(exe, "/var/lib/watchpost", "127.0.0.1:8080", false, ""); e != nil {
		t.Fatal(e)
	}
	priorUnit, _ := os.ReadFile(UnitPath)
	if !strings.Contains(string(priorUnit), "Managed by watchpost") {
		t.Fatal("installed unit lacks the managed marker")
	}
	r.script["systemctl is-enabled watchpost.service"] = fakeResult{out: "enabled", code: 0}
	r.script["systemctl is-active watchpost.service"] = fakeResult{out: "active", code: 0}
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost.service"] = fakeResult{out: "failed to enable", code: 3}
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	r.script["systemctl start watchpost.service"] = fakeResult{}
	if e := Install(exe, "/var/lib/watchpost", "127.0.0.1:9090", false, ""); e == nil {
		t.Fatal("failed reinstall returned nil")
	}
	got, _ := os.ReadFile(UnitPath)
	if string(got) != string(priorUnit) {
		t.Fatalf("reinstall failure did not restore the prior unit")
	}
}

func TestStatusReportsStates(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	r.script["systemctl is-enabled watchpost.service"] = fakeResult{out: "enabled", code: 0}
	r.script["systemctl is-active watchpost.service"] = fakeResult{out: "active", code: 0}
	r.script["systemctl show -p MainPID --value watchpost.service"] = fakeResult{out: "1234", code: 0}
	h := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok"}`))
	}))
	defer h.Close()
	listen := strings.TrimPrefix(h.URL, "http://")
	writeFileAtomic(UnitPath, []byte(Unit(DefaultDataDir, listen, false, "")), 0o644)
	var buf bytes.Buffer
	if e := Status(&buf); e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"unit:    watchpost.service", "enabled: enabled", "active:  active", "pid:     1234", "data:    /var/lib/watchpost", "health:  ok"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("status output missing %q", want)
		}
	}
	r2 := setupService(t)
	_ = r2
	os.Remove(UnitPath)
	if e := Status(io.Discard); e == nil {
		t.Fatal("status succeeded without an installed unit")
	}
}

func TestLogsConstruction(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	if e := Logs(false, io.Discard); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "journalctl --unit watchpost.service") {
		t.Fatal("logs did not run journalctl --unit")
	}
	r.log = nil
	if e := Logs(true, io.Discard); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "journalctl --unit watchpost.service -f") {
		t.Fatal("follow did not add -f")
	}
}

func TestUninstallPreservesDataAndIsIdempotent(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	r.script["systemctl disable --now watchpost.service"] = fakeResult{}
	r.script["systemctl daemon-reload"] = fakeResult{}
	if e := Uninstall(); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(UnitPath); !os.IsNotExist(e) {
		t.Fatal("unit file not removed")
	}
	r.log = nil
	if e := Uninstall(); e == nil {
		t.Fatal("uninstall of a missing unit should report not-installed")
	}
}

func TestReinstallChangedBinaryRestarts(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# different binary\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost.service"] = fakeResult{}
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	if e := Install(exe, "/var/lib/watchpost", "127.0.0.1:8080", false, ""); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "systemctl restart watchpost.service") {
		t.Fatal("changed binary did not trigger a restart")
	}
}

func TestReinstallSameBinaryIsNoOp(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, mustRead(t, BinaryPath), 0o755)
	if e := Install(exe, "/var/lib/watchpost", "127.0.0.1:8080", false, ""); e != nil {
		t.Fatal(e)
	}
	for _, call := range r.log {
		if strings.HasPrefix(call, "systemctl daemon-reload") {
			t.Fatal("identical reinstall performed a daemon-reload")
		}
	}
}

func TestReinstallRestoresExactNegativeState(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "disabled", "inactive")
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# new\nexit 0\n"), 0o755)
	// Forward path for a disabled+inactive prior: daemon-reload, disable, stop.
	// Force the forward stop to fail (1st call); rollback's stop succeeds (2nd).
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl disable watchpost.service"] = fakeResult{}
	r.seq["systemctl stop watchpost.service"] = []fakeResult{{out: "activation failed", code: 1}, {}}
	if e := Install(exe, "/var/lib/watchpost", "127.0.0.1:9090", false, ""); e == nil {
		t.Fatal("failed reinstall returned nil")
	}
	disableCalls, stopCalls := 0, 0
	for _, call := range r.log {
		if call == "systemctl disable watchpost.service" {
			disableCalls++
		}
		if call == "systemctl stop watchpost.service" {
			stopCalls++
		}
	}
	if disableCalls < 2 {
		t.Fatalf("negative enabled state not re-applied during rollback (disable calls=%d)", disableCalls)
	}
	if stopCalls < 1 {
		t.Fatalf("negative active state not re-applied during rollback (stop calls=%d)", stopCalls)
	}
	b, _ := os.ReadFile(UnitPath)
	if !strings.Contains(string(b), "127.0.0.1:8080") {
		t.Fatal("prior unit not restored after failed reinstall")
	}
}

func TestUninstallSurfacesStopDisableFailure(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	r.script["systemctl disable --now watchpost.service"] = fakeResult{out: "cannot stop", code: 1}
	if e := Uninstall(); e == nil {
		t.Fatal("uninstall ignored a failed disable --now")
	}
	if _, e := os.Stat(UnitPath); os.IsNotExist(e) {
		t.Fatal("uninstall removed the unit despite the failed stop/disable")
	}
}

func TestMalformedManagedUnitClassified(t *testing.T) {
	setupService(t)
	writeFileAtomic(UnitPath, []byte("# Managed by watchpost. Do not edit manually.\n[Unit]\n[Service]\n[Install]\n"), 0o644)
	if e := lifecycle("start"); e == nil {
		t.Fatal("malformed managed unit accepted for start")
	}
	if e := Status(io.Discard); e == nil {
		t.Fatal("malformed managed unit accepted for status")
	}
}

func TestTamperedManagedUnitRejected(t *testing.T) {
	setupService(t)
	u := Unit(DefaultDataDir, "127.0.0.1:8080", false, "")
	// Tamper with the body (change the listen) without updating the checksum.
	tampered := strings.Replace(u, "127.0.0.1:8080", "127.0.0.1:9090", 1)
	writeFileAtomic(UnitPath, []byte(tampered), 0o644)
	if e := lifecycle("start"); e == nil {
		t.Fatal("tampered managed unit accepted for start")
	}
	if e := Status(io.Discard); e == nil {
		t.Fatal("tampered managed unit accepted for status")
	}
}

func TestUpdateAndRollbackRefuseForeignUnit(t *testing.T) {
	setupService(t)
	writeFileAtomic(UnitPath, []byte("[Unit]\nDescription=admin\n[Service]\nExecStart=/usr/bin/thing\n[Install]\nWantedBy=multi-user.target\n"), 0o644)
	before, _ := os.ReadFile(BinaryPath)
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("update mutated a foreign unit")
	}
	if e := Rollback(); e == nil {
		t.Fatal("rollback mutated a foreign unit")
	}
	after, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(before, after) {
		t.Fatal("update/rollback mutated the binary of a foreign unit")
	}
}

func TestUpdatePreservesActiveState(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "systemctl restart watchpost.service") {
		t.Fatal("active update did not restart")
	}
	r.log = nil
	setState(r, "enabled", "inactive")
	prepareUpdate(r, "inactive", true)
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	for _, call := range r.log {
		if strings.Contains(call, "restart watchpost.service") || strings.Contains(call, "start watchpost.service") {
			t.Fatalf("stopped update started the service: %s", call)
		}
	}
}

func TestUpdateFailedActivationRestoresOldBinaryAndActive(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart watchpost.service"] = fakeResult{out: "activation failed", code: 1}
	r.script["systemctl stop watchpost.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("failed activation update returned nil")
	}
	now, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("failed activation did not restore the old binary")
	}
}

func TestRollbackRestoresStoppedStateWithoutStarting(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	setState(r, "enabled", "inactive")
	prepareUpdate(r, "inactive", true)
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	r.log = nil
	if e := Rollback(); e != nil {
		t.Fatal(e)
	}
	now, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("rollback did not restore the old binary")
	}
	for _, call := range r.log {
		if strings.Contains(call, "restart watchpost.service") || strings.Contains(call, "start watchpost.service") {
			t.Fatalf("rollback of a stopped service started it: %s", call)
		}
	}
}

func TestRollbackRestoresRunningState(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	r.log = nil
	if e := Rollback(); e != nil {
		t.Fatal(e)
	}
	if !contains(r.log, "systemctl restart watchpost.service") {
		t.Fatal("rollback of an active service did not restart it")
	}
	if _, e := os.Stat(BinaryPath + ".rollback"); !os.IsNotExist(e) {
		t.Fatal("rollback metadata not consumed after successful rollback")
	}
	for _, call := range r.log {
		if strings.HasPrefix(call, "systemctl enable ") || strings.HasPrefix(call, "systemctl disable ") {
			t.Fatalf("update/rollback changed enablement: %s", call)
		}
	}
}

func TestUpdateVerifiesHealthNotJustRestartExit(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", false)
	healthWindow = 1 * time.Second
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	r.script["systemctl stop watchpost.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("update succeeded although the new binary never became healthy")
	}
	now, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("unhealthy update did not restore the old binary")
	}
}

func TestUpdateActiveStateQueryFailureAborts(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl is-active watchpost.service"] = fakeResult{out: "", code: 1, err: fmt.Errorf("systemctl is-active failed")}
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("update proceeded when the active state could not be determined")
	}
	now, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("state-query failure still mutated the binary")
	}
}

func TestUpdatePriorStateMarkerWriteFailureAborts(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	setState(r, "enabled", "inactive")
	r.script["systemctl is-active watchpost.service"] = fakeResult{out: "inactive", code: 0}
	os.MkdirAll(BinaryPath+".prior-active", 0o700)
	if e := Update(exe, fakeSHA(exe)); e == nil {
		t.Fatal("update proceeded when the rollback marker could not be written")
	}
	now, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(now, oldBin) {
		t.Fatal("marker-write failure still mutated the binary")
	}
}

func TestRollbackFailClosedWithoutMarker(t *testing.T) {
	setupService(t)
	installManagedUnit(t)
	os.WriteFile(BinaryPath+".rollback", []byte("#!/bin/sh\nexit 0\n"), 0o755)
	os.Remove(BinaryPath + ".prior-active")
	if e := Rollback(); e == nil {
		t.Fatal("rollback defaulted to active without a prior-state marker")
	}
}

func TestEndToEndActiveUpdateThenRollback(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(BinaryPath + ".rollback"); e != nil {
		t.Fatal("rollback binary missing after successful update")
	}
	if _, e := os.Stat(BinaryPath + ".prior-active"); e != nil {
		t.Fatal("prior-active marker missing after successful update")
	}
	now, _ := os.ReadFile(BinaryPath)
	if bytes.Equal(now, oldBin) {
		t.Fatal("update did not replace the binary")
	}
	r.log = nil
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	if e := Rollback(); e != nil {
		t.Fatal(e)
	}
	back, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(back, oldBin) {
		t.Fatal("rollback did not restore the old binary")
	}
	if !contains(r.log, "systemctl restart watchpost.service") {
		t.Fatal("rollback of an active service did not restart it")
	}
}

func TestEndToEndStoppedUpdateThenRollback(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	setState(r, "enabled", "inactive")
	prepareUpdate(r, "inactive", true)
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	if e := Update(exe, fakeSHA(exe)); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(BinaryPath + ".prior-active"); e != nil {
		t.Fatal("prior-active marker missing after stopped update")
	}
	r.log = nil
	if e := Rollback(); e != nil {
		t.Fatal(e)
	}
	back, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(back, oldBin) {
		t.Fatal("rollback did not restore the old binary")
	}
	for _, call := range r.log {
		if strings.Contains(call, "restart watchpost.service") || strings.Contains(call, "start watchpost.service") {
			t.Fatalf("rollback of a stopped service started it: %s", call)
		}
	}
}

func TestFailedUpdateRecoverySurfacesFailures(t *testing.T) {
	{
		r := setupService(t)
		installManagedUnit(t)
		setState(r, "enabled", "active")
		prepareUpdate(r, "active", false)
		healthWindow = 1 * time.Second
		exe := filepath.Join(t.TempDir(), "wp2")
		os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
		r.script["systemctl restart watchpost.service"] = fakeResult{}
		r.script["systemctl stop watchpost.service"] = fakeResult{}
		r.seq["systemctl restart watchpost.service"] = []fakeResult{{}, {out: "restore failed", code: 1}}
		uerr := Update(exe, fakeSHA(exe))
		if uerr == nil {
			t.Fatal("update succeeded despite a failed recovery restart")
		}
		if !strings.Contains(uerr.Error(), "recovery") {
			t.Fatalf("recovery restart failure not surfaced: %v", uerr)
		}
	}
	{
		r := setupService(t)
		installManagedUnit(t)
		setState(r, "enabled", "active")
		prepareUpdate(r, "active", false)
		healthWindow = 1 * time.Second
		exe := filepath.Join(t.TempDir(), "wp2")
		os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
		r.script["systemctl restart watchpost.service"] = fakeResult{}
		r.script["systemctl stop watchpost.service"] = fakeResult{out: "cannot stop", code: 1}
		uerr := Update(exe, fakeSHA(exe))
		if uerr == nil {
			t.Fatal("update succeeded despite a failed recovery stop")
		}
		if !strings.Contains(uerr.Error(), "recovery") {
			t.Fatalf("recovery stop failure not surfaced: %v", uerr)
		}
	}
}

func TestInitialRestartFailureSurfacesRecoveryFailure(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.seq["systemctl restart watchpost.service"] = []fakeResult{
		{out: "new binary failed to start", code: 1},
		{out: "recovery restart failed", code: 1},
	}
	r.script["systemctl stop watchpost.service"] = fakeResult{}
	uerr := Update(exe, fakeSHA(exe))
	if uerr == nil {
		t.Fatal("update succeeded despite initial restart failure")
	}
	if !strings.Contains(uerr.Error(), "restart after update") {
		t.Fatalf("original restart failure missing: %v", uerr)
	}
	if !strings.Contains(uerr.Error(), "recovery") {
		t.Fatalf("recovery failure not surfaced: %v", uerr)
	}
}

func TestInitialRestartFailureRecoverySucceedsCleansMetadata(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	oldBin := mustRead(t, BinaryPath)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", true)
	healthWindow = 1 * time.Second
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.seq["systemctl restart watchpost.service"] = []fakeResult{
		{out: "new binary failed to start", code: 1},
		{},
	}
	r.script["systemctl stop watchpost.service"] = fakeResult{}
	uerr := Update(exe, fakeSHA(exe))
	if uerr == nil {
		t.Fatal("update should report the initial restart failure")
	}
	back, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(back, oldBin) {
		t.Fatal("recovery did not restore the old binary")
	}
	if _, e := os.Stat(BinaryPath + ".rollback"); !os.IsNotExist(e) {
		t.Fatal("stale rollback binary left after verified recovery")
	}
	if _, e := os.Stat(BinaryPath + ".prior-active"); !os.IsNotExist(e) {
		t.Fatal("stale prior-active marker left after verified recovery")
	}
}

// TestRecoveryFailsClosedWhenMarkerCorruptedAtRecoveryTime is the corrected
// real-sequence regression: the marker is written by Update, the new binary is
// activated, the health check fails, and only THEN is the marker corrupted (via
// a narrow injectable read seam) so recovery must fail closed rather than guess
// to active.
func TestRecoveryFailsClosedWhenMarkerCorruptedAtRecoveryTime(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", false)
	healthWindow = 1 * time.Second
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	r.script["systemctl stop watchpost.service"] = fakeResult{}
	// The real sequence: Update writes the marker before touching the binary.
	// We inject the corruption at the recovery read by returning an invalid
	// marker ONLY at the recovery-time read, after Update's own write has
	// completed (the seam is read by recovery, not by Update's initial write).
	orig := priorStateFileRead
	priorStateFileRead = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, ".prior-active") {
			// Return corrupt content (not the valid marker Update wrote).
			return []byte("garbage"), nil
		}
		return os.ReadFile(path)
	}
	defer func() { priorStateFileRead = orig }()
	uerr := Update(exe, fakeSHA(exe))
	if uerr == nil {
		t.Fatal("update succeeded despite corrupted recovery marker")
	}
	if !strings.Contains(uerr.Error(), "recovery") {
		t.Fatalf("recovery fail-closed degradation not surfaced: %v", uerr)
	}
}

// TestRecoveryFailsClosedWhenMarkerMissingAtRecoveryTime proves recovery does
// not guess to active when the marker disappears at recovery time (after Update
// wrote it), without test-side fabrication before Update.
func TestRecoveryFailsClosedWhenMarkerMissingAtRecoveryTime(t *testing.T) {
	r := setupService(t)
	installManagedUnit(t)
	setState(r, "enabled", "active")
	prepareUpdate(r, "active", false)
	healthWindow = 1 * time.Second
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	r.script["systemctl stop watchpost.service"] = fakeResult{}
	orig := priorStateFileRead
	priorStateFileRead = func(path string) ([]byte, error) {
		if strings.HasSuffix(path, ".prior-active") {
			return nil, fmt.Errorf("marker vanished")
		}
		return os.ReadFile(path)
	}
	defer func() { priorStateFileRead = orig }()
	uerr := Update(exe, fakeSHA(exe))
	if uerr == nil {
		t.Fatal("update succeeded despite missing recovery marker")
	}
	if !strings.Contains(uerr.Error(), "recovery") {
		t.Fatalf("recovery fail-closed degradation not surfaced: %v", uerr)
	}
}

func TestRollbackEnforcesManagedUnitBeforeBinary(t *testing.T) {
	setupService(t)
	writeFileAtomic(UnitPath, []byte("[Unit]\nDescription=admin\n[Service]\nExecStart=/usr/bin/thing\n[Install]\nWantedBy=multi-user.target\n"), 0o644)
	before, _ := os.ReadFile(BinaryPath)
	if e := Rollback(); e == nil {
		t.Fatal("rollback of a foreign unit succeeded")
	}
	if e := Update(filepath.Join(t.TempDir(), "x"), "x"); e == nil {
		t.Fatal("update of a foreign unit succeeded")
	}
	after, _ := os.ReadFile(BinaryPath)
	if !bytes.Equal(before, after) {
		t.Fatal("update/rollback mutated binary before the managed-unit check")
	}
}

func TestUnitOptionsExplicitHostPort(t *testing.T) {
	setupService(t)
	o := Options{DataDir: "/var/lib/watchpost", Host: "0.0.0.0", Port: "7404"}
	u := UnitOptions(o)
	for _, want := range []string{`"--host" "0.0.0.0"`, `"--port" "7404"`, `# watchpost-listen: 0.0.0.0:7404`, `# watchpost-listen-mode: explicit`} {
		if !strings.Contains(u, want) {
			t.Fatalf("unit missing %q\n%s", want, u)
		}
	}
	if strings.Contains(u, "--listen") {
		t.Fatalf("explicit unit must not use legacy --listen\n%s", u)
	}
	if _, err := readManagedUnit(u); err != nil {
		t.Fatalf("explicit unit should validate: %v", err)
	}
}

func TestUnitDefaultListenIsCanonical(t *testing.T) {
	setupService(t)
	// A default install resolves to 127.0.0.1:7334; the unit records it through
	// --host/--port so the listener survives restart and reboot.
	o := Options{DataDir: "/var/lib/watchpost", Host: "127.0.0.1", Port: "7334"}
	u := UnitOptions(o)
	for _, want := range []string{`"--host" "127.0.0.1"`, `"--port" "7334"`, `# watchpost-listen: 127.0.0.1:7334`, `# watchpost-listen-mode: explicit`} {
		if !strings.Contains(u, want) {
			t.Fatalf("default unit missing %q\n%s", want, u)
		}
	}
	if _, err := readManagedUnit(u); err != nil {
		t.Fatalf("default unit should validate: %v", err)
	}
}

func TestUnitOptionsCanonicalWhitespace(t *testing.T) {
	setupService(t)
	// Whitespace-surrounded host/port must never leak into the unit metadata or
	// ExecStart; only the canonical trimmed values are recorded.
	o := Options{DataDir: "/var/lib/watchpost", Host: "  127.0.0.1  ", Port: "  7402  "}
	u := UnitOptions(o)
	for _, want := range []string{`"--host" "127.0.0.1"`, `"--port" "7402"`, `# watchpost-listen: 127.0.0.1:7402`} {
		if !strings.Contains(u, want) {
			t.Fatalf("canonical unit missing %q\n%s", want, u)
		}
	}
	for _, bad := range []string{`"  127.0.0.1  "`, `"  7402  "`, `# watchpost-listen:   127.0.0.1:7402`} {
		if strings.Contains(u, bad) {
			t.Fatalf("unit leaked untrimmed value %q\n%s", bad, u)
		}
	}
}

func TestUnitLegacyBootstrapMode(t *testing.T) {
	setupService(t)
	u := Unit(DefaultDataDir, "127.0.0.1:8080", false, "")
	if !strings.Contains(u, `"--listen" "127.0.0.1:8080"`) {
		t.Fatalf("legacy unit missing --listen\n%s", u)
	}
	if !strings.Contains(u, "# watchpost-listen-mode: bootstrap") {
		t.Fatalf("legacy unit missing bootstrap mode marker\n%s", u)
	}
	if _, err := readManagedUnit(u); err != nil {
		t.Fatalf("legacy unit should validate: %v", err)
	}
}

func TestListenModeMarkers(t *testing.T) {
	setupService(t)
	explicit := UnitOptions(Options{DataDir: "/var/lib/watchpost", Host: "127.0.0.1", Port: "7402"})
	if !strings.Contains(explicit, "# watchpost-listen-mode: explicit") {
		t.Fatalf("explicit unit missing explicit mode marker\n%s", explicit)
	}
	m, err := readManagedUnit(explicit)
	if err != nil {
		t.Fatal(err)
	}
	if m.listenMode != listenModeExplicit {
		t.Fatalf("explicit unit listenMode = %q", m.listenMode)
	}
	legacy := Unit(DefaultDataDir, "127.0.0.1:8080", false, "")
	m, err = readManagedUnit(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if m.listenMode != listenModeBootstrap {
		t.Fatalf("legacy unit listenMode = %q", m.listenMode)
	}
	// A hostile mode value is rejected.
	bad := strings.Replace(legacy, "# watchpost-listen-mode: bootstrap", "# watchpost-listen-mode: attacker", 1)
	if _, err := readManagedUnit(bad); err == nil {
		t.Fatal("invalid listen-mode accepted")
	}
	// A duplicate mode marker is rejected.
	dup := strings.Replace(legacy, "# watchpost-listen-mode: bootstrap", "# watchpost-listen-mode: bootstrap\n# watchpost-listen-mode: bootstrap", 1)
	if _, err := readManagedUnit(dup); err == nil {
		t.Fatal("duplicate listen-mode accepted")
	}
}

func TestLegacyUnitWithoutModeMarkerDefaultsToBootstrap(t *testing.T) {
	setupService(t)
	// A unit written before the mode marker existed must still validate and be
	// classified bootstrap, keeping legacy durable-listen behaviour.
	body := unitBody(Options{DataDir: "/var/lib/watchpost", Listen: "127.0.0.1:8080"})
	content := "# watchpost-listen: 127.0.0.1:8080\n# watchpost-data: /var/lib/watchpost\n# watchpost-health: /healthz\n" + body
	sum := sha256.Sum256([]byte(content))
	unit := watchpostUnitMarker + "\n" + watchpostManagedPrefix + "v1 sha256=" + hex.EncodeToString(sum[:]) + "\n" + content
	m, err := readManagedUnit(unit)
	if err != nil {
		t.Fatalf("legacy unit without mode marker should validate: %v", err)
	}
	if m.listenMode != listenModeBootstrap {
		t.Fatalf("missing marker must default to bootstrap, got %q", m.listenMode)
	}
	if m.listen != "127.0.0.1:8080" {
		t.Fatalf("legacy recorded listen = %q", m.listen)
	}
}

func TestStatusReportsExplicitUnitListener(t *testing.T) {
	r := setupService(t)
	setState(r, "enabled", "active")
	r.script["systemctl show -p MainPID --value watchpost.service"] = fakeResult{out: "99", code: 0}
	var got string
	healthCheckFunc = func(url string) error { got = url; return nil }
	writeFileAtomic(UnitPath, []byte(UnitOptions(Options{DataDir: "/var/lib/watchpost", Host: "127.0.0.1", Port: "7404"})), 0o644)
	var buf bytes.Buffer
	if e := Status(&buf); e != nil {
		t.Fatal(e)
	}
	for _, want := range []string{"listen:  127.0.0.1:7404", "health:  ok"} {
		if !strings.Contains(buf.String(), want) {
			t.Fatalf("status output missing %q\n%s", want, buf.String())
		}
	}
	if !strings.HasPrefix(got, "http://127.0.0.1:7404") {
		t.Fatalf("health check must target the recorded explicit listener, got %q", got)
	}
}

func TestStatusLegacyBootstrapUnitReportsRecordedListener(t *testing.T) {
	r := setupService(t)
	setState(r, "enabled", "active")
	r.script["systemctl show -p MainPID --value watchpost.service"] = fakeResult{out: "7", code: 0}
	healthCheckFunc = func(url string) error { return nil }
	writeFileAtomic(UnitPath, []byte(Unit(DefaultDataDir, "127.0.0.1:8080", false, "")), 0o644)
	var buf bytes.Buffer
	if e := Status(&buf); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(buf.String(), "listen:  127.0.0.1:8080") {
		t.Fatalf("legacy bootstrap status must report the recorded durable listener\n%s", buf.String())
	}
}

func TestStatusIgnoresMalformedListenerEnv(t *testing.T) {
	// Non-install service commands must ignore malformed WATCHPOST_HOST/
	// WATCHPOST_PORT in the invoking shell.
	r := setupService(t)
	t.Setenv("WATCHPOST_HOST", "not a host")
	t.Setenv("WATCHPOST_PORT", "not-a-port")
	setState(r, "enabled", "active")
	r.script["systemctl show -p MainPID --value watchpost.service"] = fakeResult{out: "7", code: 0}
	healthCheckFunc = func(url string) error { return nil }
	writeFileAtomic(UnitPath, []byte(UnitOptions(Options{DataDir: "/var/lib/watchpost", Host: "127.0.0.1", Port: "7404"})), 0o644)
	var buf bytes.Buffer
	if e := Status(&buf); e != nil {
		t.Fatalf("status must ignore malformed listener env: %v", e)
	}
	if !strings.Contains(buf.String(), "listen:  127.0.0.1:7404") {
		t.Fatalf("status output missing recorded listener\n%s", buf.String())
	}
}

func TestReinstallExplicitHostPortChangesListener(t *testing.T) {
	r := setupService(t)
	setState(r, "enabled", "active")
	exe := filepath.Join(t.TempDir(), "wp2")
	os.WriteFile(exe, []byte("#!/bin/sh\n# v2\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost.service"] = fakeResult{}
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	o1 := Options{DataDir: "/var/lib/watchpost", Host: "127.0.0.1", Port: "7402"}
	if e := InstallOptions(exe, o1); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(UnitPath)
	if !strings.Contains(string(b), `"--port" "7402"`) {
		t.Fatalf("first install must record 7402\n%s", b)
	}
	if !strings.Contains(string(b), "# watchpost-listen-mode: explicit") {
		t.Fatalf("first install must be explicit mode\n%s", b)
	}
	// A changed --port rewrites the unit's --host/--port and restarts.
	exe2 := filepath.Join(t.TempDir(), "wp3")
	os.WriteFile(exe2, []byte("#!/bin/sh\n# v3\nexit 0\n"), 0o755)
	r.log = nil
	o2 := Options{DataDir: "/var/lib/watchpost", Host: "127.0.0.1", Port: "7403"}
	if e := InstallOptions(exe2, o2); e != nil {
		t.Fatalf("reinstall: %v", e)
	}
	b, _ = os.ReadFile(UnitPath)
	if !strings.Contains(string(b), `"--port" "7403"`) {
		t.Fatalf("reinstall must record 7403\n%s", b)
	}
	if !strings.Contains(string(b), "# watchpost-listen-mode: explicit") {
		t.Fatalf("reinstall unit must remain explicit mode\n%s", b)
	}
	if !contains(r.log, "systemctl restart watchpost.service") {
		t.Fatalf("changed listener must restart the service\ncalls: %v", r.log)
	}
}

func TestInstallOptionsLegacyBootstrapMode(t *testing.T) {
	r := setupService(t)
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost.service"] = fakeResult{}
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	if e := InstallOptions(exe, Options{DataDir: "/var/lib/watchpost", Listen: "127.0.0.1:8080"}); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(UnitPath)
	if !strings.Contains(string(b), `"--listen" "127.0.0.1:8080"`) {
		t.Fatalf("legacy install must record --listen\n%s", b)
	}
	if !strings.Contains(string(b), "# watchpost-listen-mode: bootstrap") {
		t.Fatalf("legacy install must be bootstrap mode\n%s", b)
	}
}

func TestInstallOptionsExplicitDefaultListener(t *testing.T) {
	r := setupService(t)
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost.service"] = fakeResult{}
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	// A bare CLI install resolves the fresh default 127.0.0.1:7334 and records
	// it through canonical --host/--port.
	if e := InstallOptions(exe, Options{DataDir: "/var/lib/watchpost", Host: "127.0.0.1", Port: "7334"}); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(UnitPath)
	if !strings.Contains(string(b), `"--host" "127.0.0.1"`) || !strings.Contains(string(b), `"--port" "7334"`) {
		t.Fatalf("default install must record --host 127.0.0.1 --port 7334\n%s", b)
	}
	if !strings.Contains(string(b), "# watchpost-listen: 127.0.0.1:7334") {
		t.Fatalf("default install must record the canonical listener\n%s", b)
	}
	if !strings.Contains(string(b), "# watchpost-listen-mode: explicit") {
		t.Fatalf("default install must be explicit mode\n%s", b)
	}
}

func TestInstallLegacyEmptyListenDefaultsToBootstrapDefault(t *testing.T) {
	r := setupService(t)
	exe := filepath.Join(t.TempDir(), "wp")
	os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755)
	r.script["systemctl daemon-reload"] = fakeResult{}
	r.script["systemctl enable watchpost.service"] = fakeResult{}
	r.script["systemctl restart watchpost.service"] = fakeResult{}
	// The legacy Install wrapper with an empty listen defaults to the fresh
	// DefaultListen in bootstrap mode, preserving the durable-config contract.
	if e := Install(exe, "/var/lib/watchpost", "", false, ""); e != nil {
		t.Fatal(e)
	}
	b, _ := os.ReadFile(UnitPath)
	if !strings.Contains(string(b), `"--listen" "127.0.0.1:7334"`) {
		t.Fatalf("legacy empty-listen install must record --listen 127.0.0.1:7334\n%s", b)
	}
	if !strings.Contains(string(b), "# watchpost-listen-mode: bootstrap") {
		t.Fatalf("legacy empty-listen install must be bootstrap mode\n%s", b)
	}
}
