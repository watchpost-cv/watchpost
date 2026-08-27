package config

import (
	"path/filepath"
	"testing"
)

func TestLoadPrecedence(t *testing.T) {
	t.Setenv("WATCHPOST_LISTEN", "127.0.0.1:9000")
	t.Setenv("WATCHPOST_DATA_DIR", filepath.Join(t.TempDir(), "environment"))
	wantDir := filepath.Join(t.TempDir(), "flag")
	cfg, err := Load(Overrides{Listen: "127.0.0.1:9001", DataDir: wantDir})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:9001" || cfg.DataDir != wantDir {
		t.Fatalf("unexpected config: %#v", cfg)
	}
}

func TestLoadRejectsInvalidValues(t *testing.T) {
	for _, tc := range []Overrides{{Listen: "not-an-address"}, {DataDir: "relative"}} {
		if _, err := Load(tc); err == nil {
			t.Fatalf("Load(%#v) succeeded", tc)
		}
	}
}
