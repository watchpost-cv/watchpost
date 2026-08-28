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
	if len(calls) != 2 || !strings.Contains(calls[1], "enable --now") {
		t.Fatalf("calls %#v", calls)
	}
}
