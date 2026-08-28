package collectorservice

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInstallCreatesHardenedStableService(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	config := filepath.Join(directory, "state", "collector.json")
	paths := Paths{Binary: filepath.Join(directory, "bin", "watchpost"), Config: config, Unit: filepath.Join(directory, "watchpost.service")}
	_ = os.MkdirAll(filepath.Dir(config), 0700)
	_ = os.WriteFile(source, []byte("binary"), 0755)
	_ = os.WriteFile(config, []byte(`{}`), 0600)
	var calls []string
	manager := Manager{Run: func(name string, args ...string) error {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return nil
	}}
	if err := manager.Install(source, paths); err != nil {
		t.Fatal(err)
	}
	unit, _ := os.ReadFile(paths.Unit)
	text := string(unit)
	for _, required := range []string{"NoNewPrivileges=true", "ProtectSystem=strict", "UMask=0077", paths.Binary, paths.Config} {
		if !strings.Contains(text, required) {
			t.Fatalf("unit missing %s", required)
		}
	}
	if len(calls) != 3 || !strings.Contains(calls[1], "enable watchpost-collector.service") || !strings.Contains(calls[2], "restart watchpost-collector.service") {
		t.Fatalf("calls %#v", calls)
	}
	installed, err := os.ReadFile(paths.Binary)
	if err != nil || string(installed) != "binary" {
		t.Fatalf("installed binary=%q err=%v", installed, err)
	}
}

func TestInstallAtomicallyReplacesExistingBinary(t *testing.T) {
	directory := t.TempDir()
	source := filepath.Join(directory, "source")
	destination := filepath.Join(directory, "bin", "watchpost")
	if err := os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(source, []byte("new binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("running binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := copyFile(source, destination, 0755); err != nil {
		t.Fatal(err)
	}
	installed, err := os.ReadFile(destination)
	if err != nil || string(installed) != "new binary" {
		t.Fatalf("installed=%q err=%v", installed, err)
	}
	matches, err := filepath.Glob(filepath.Join(filepath.Dir(destination), ".watchpost-install-*"))
	if err != nil || len(matches) != 0 {
		t.Fatalf("temporary files=%v err=%v", matches, err)
	}
}
