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

func TestSecureCookiesFromEnvironmentAndOverride(t *testing.T) {
	t.Setenv("WATCHPOST_SECURE_COOKIES", "true")
	cfg, err := Load(Overrides{})
	if err != nil || !cfg.SecureCookies {
		t.Fatalf("cfg=%#v err=%v", cfg, err)
	}
	t.Setenv("WATCHPOST_SECURE_COOKIES", "")
	cfg, err = Load(Overrides{SecureCookies: true})
	if err != nil || !cfg.SecureCookies {
		t.Fatalf("cfg=%#v err=%v", cfg, err)
	}
}

func TestReplicationEnvLoadsFullConfig(t *testing.T) {
	t.Setenv("WATCHPOST_REPLICATION_ENABLED", "true")
	t.Setenv("WATCHPOST_REPLICATION_NODE_ID", "node-1")
	t.Setenv("WATCHPOST_REPLICATION_BOOTSTRAP", "true")
	t.Setenv("WATCHPOST_REPLICATION_LISTEN", "127.0.0.1:7335")
	t.Setenv("WATCHPOST_REPLICATION_TLS_CERT", "/etc/watchpost/raft.crt")
	t.Setenv("WATCHPOST_REPLICATION_TLS_KEY", "/etc/watchpost/raft.key")
	t.Setenv("WATCHPOST_REPLICATION_TLS_CA", "/etc/watchpost/ca.crt")
	cfg, err := Load(Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	r := cfg.Replication
	if !r.Enabled || r.NodeID != "node-1" || !r.Bootstrap || r.Listen != "127.0.0.1:7335" ||
		r.TLSCert != "/etc/watchpost/raft.crt" || r.TLSKey != "/etc/watchpost/raft.key" || r.TLSCA != "/etc/watchpost/ca.crt" || r.InsecurePlaintext {
		t.Fatalf("unexpected replication config: %#v", r)
	}
}

func TestReplicationDisabledRequiresNothing(t *testing.T) {
	if _, err := Load(Overrides{}); err != nil {
		t.Fatalf("standalone load: %v", err)
	}
}

func TestReplicationEnabledFailsClosed(t *testing.T) {
	cases := []struct {
		name     string
		override [][2]string
	}{
		{"missing listen", [][2]string{{"WATCHPOST_REPLICATION_LISTEN", ""}}},
		{"invalid listen", [][2]string{{"WATCHPOST_REPLICATION_LISTEN", "not-an-address"}}},
		{"cert only", [][2]string{{"WATCHPOST_REPLICATION_TLS_KEY", ""}, {"WATCHPOST_REPLICATION_TLS_CA", ""}}},
		{"missing ca", [][2]string{{"WATCHPOST_REPLICATION_TLS_CA", ""}}},
		{"no tls no insecure", [][2]string{{"WATCHPOST_REPLICATION_TLS_CERT", ""}, {"WATCHPOST_REPLICATION_TLS_KEY", ""}, {"WATCHPOST_REPLICATION_TLS_CA", ""}}},
		{"tls plus insecure contradiction", [][2]string{{"WATCHPOST_REPLICATION_INSECURE_PLAINTEXT", "true"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("WATCHPOST_REPLICATION_ENABLED", "true")
			t.Setenv("WATCHPOST_REPLICATION_NODE_ID", "node-1")
			t.Setenv("WATCHPOST_REPLICATION_LISTEN", "127.0.0.1:7335")
			t.Setenv("WATCHPOST_REPLICATION_TLS_CERT", "/etc/watchpost/raft.crt")
			t.Setenv("WATCHPOST_REPLICATION_TLS_KEY", "/etc/watchpost/raft.key")
			t.Setenv("WATCHPOST_REPLICATION_TLS_CA", "/etc/watchpost/ca.crt")
			for _, kv := range tc.override {
				t.Setenv(kv[0], kv[1])
			}
			if _, err := Load(Overrides{}); err == nil {
				t.Fatal("Load succeeded; expected fail-closed error")
			}
		})
	}
}

func TestReplicationExplicitInsecureAllowed(t *testing.T) {
	t.Setenv("WATCHPOST_REPLICATION_ENABLED", "true")
	t.Setenv("WATCHPOST_REPLICATION_NODE_ID", "node-1")
	t.Setenv("WATCHPOST_REPLICATION_LISTEN", "127.0.0.1:7335")
	t.Setenv("WATCHPOST_REPLICATION_INSECURE_PLAINTEXT", "true")
	cfg, err := Load(Overrides{})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.Replication.Enabled || !cfg.Replication.InsecurePlaintext {
		t.Fatalf("expected explicit insecure opt-in: %#v", cfg.Replication)
	}
}
