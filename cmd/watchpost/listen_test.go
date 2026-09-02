package main

import (
	"flag"
	"os"
	"strings"
	"testing"
)

// listenerFlags parses raw argv through the same flag definitions the CLI uses
// so "provided but empty" (--host "") is distinguishable from "not provided".
func listenerFlags(args ...string) (h, p, l string, hs, ps, ls bool) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("host", "", "")
	fs.String("port", "", "")
	fs.String("listen", "", "")
	_ = fs.Parse(args)
	return fs.Lookup("host").Value.String(),
		fs.Lookup("port").Value.String(),
		fs.Lookup("listen").Value.String(),
		flagProvided(fs, "host"),
		flagProvided(fs, "port"),
		flagProvided(fs, "listen")
}

func TestResolveListenerDefaults(t *testing.T) {
	os.Unsetenv("WATCHPOST_HOST")
	os.Unsetenv("WATCHPOST_PORT")
	os.Unsetenv("WATCHPOST_LISTEN")
	h, p, l, hs, ps, ls := listenerFlags()
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:7334" {
		t.Fatalf("default listener = %q want 127.0.0.1:7334", addr)
	}
}

func TestResolveListenerEnvOnly(t *testing.T) {
	os.Unsetenv("WATCHPOST_LISTEN")
	t.Setenv("WATCHPOST_HOST", "0.0.0.0")
	t.Setenv("WATCHPOST_PORT", "7402")
	h, p, l, hs, ps, ls := listenerFlags()
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "0.0.0.0:7402" {
		t.Fatalf("env listener = %q want 0.0.0.0:7402", addr)
	}
}

func TestResolveListenerCLIOnly(t *testing.T) {
	os.Unsetenv("WATCHPOST_LISTEN")
	t.Setenv("WATCHPOST_HOST", "192.0.2.1")
	t.Setenv("WATCHPOST_PORT", "9999")
	h, p, l, hs, ps, ls := listenerFlags("--host", "127.0.0.1", "--port", "7402")
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:7402" {
		t.Fatalf("cli listener = %q want 127.0.0.1:7402", addr)
	}
}

func TestResolveListenerCLIOverridesEnv(t *testing.T) {
	os.Unsetenv("WATCHPOST_LISTEN")
	t.Setenv("WATCHPOST_HOST", "0.0.0.0")
	t.Setenv("WATCHPOST_PORT", "9000")
	h, p, l, hs, ps, ls := listenerFlags("--host", "127.0.0.1", "--port", "7402")
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:7402" {
		t.Fatalf("cli should override env: %q", addr)
	}
}

func TestResolveListenerInvalidPorts(t *testing.T) {
	os.Unsetenv("WATCHPOST_LISTEN")
	for _, p := range []string{"abc", "0", "-5", "65536", "70000", "7 4 0 2", "7402x"} {
		h, pp, l, hs, ps, ls := listenerFlags("--host", "127.0.0.1", "--port", p)
		if _, err := resolveListener(h, pp, l, hs, ps, ls); err == nil {
			t.Fatalf("invalid --port %q accepted", p)
		}
	}
	for _, p := range []string{"abc", "0", "-5", "65536", "70000"} {
		t.Setenv("WATCHPOST_HOST", "127.0.0.1")
		t.Setenv("WATCHPOST_PORT", p)
		h, pp, l, hs, ps, ls := listenerFlags()
		if _, err := resolveListener(h, pp, l, hs, ps, ls); err == nil {
			t.Fatalf("invalid WATCHPOST_PORT %q accepted", p)
		}
	}
}

func TestResolveListenerEmptyEnvFails(t *testing.T) {
	os.Unsetenv("WATCHPOST_LISTEN")
	t.Setenv("WATCHPOST_HOST", "127.0.0.1")
	t.Setenv("WATCHPOST_PORT", "")
	h, p, l, hs, ps, ls := listenerFlags()
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("empty WATCHPOST_PORT accepted")
	}
	t.Setenv("WATCHPOST_HOST", "")
	t.Setenv("WATCHPOST_PORT", "7334")
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("empty WATCHPOST_HOST accepted")
	}
}

func TestResolveListenerEmptyCLIValuesFail(t *testing.T) {
	os.Unsetenv("WATCHPOST_LISTEN")
	t.Setenv("WATCHPOST_HOST", "127.0.0.1")
	t.Setenv("WATCHPOST_PORT", "7334")
	h, p, l, hs, ps, ls := listenerFlags("--host", "", "--port", "7334")
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("empty --host accepted")
	}
	t.Setenv("WATCHPOST_HOST", "127.0.0.1")
	t.Setenv("WATCHPOST_PORT", "7334")
	h, p, l, hs, ps, ls = listenerFlags("--host", "127.0.0.1", "--port", "")
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("empty --port accepted")
	}
}

func TestResolveListenerIPv6(t *testing.T) {
	os.Unsetenv("WATCHPOST_LISTEN")
	t.Setenv("WATCHPOST_HOST", "::1")
	t.Setenv("WATCHPOST_PORT", "7334")
	h, p, l, hs, ps, ls := listenerFlags()
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "[::1]:7334" {
		t.Fatalf("IPv6 listener = %q want [::1]:7334", addr)
	}
}

func TestResolveListenerLegacyListen(t *testing.T) {
	os.Unsetenv("WATCHPOST_LISTEN")
	t.Setenv("WATCHPOST_HOST", "0.0.0.0")
	t.Setenv("WATCHPOST_PORT", "9000")
	h, p, l, hs, ps, ls := listenerFlags("--listen", "127.0.0.1:8080")
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:8080" {
		t.Fatalf("legacy --listen = %q", addr)
	}
	// WATCHPOST_LISTEN environment is honored as the legacy single-address form.
	os.Unsetenv("WATCHPOST_HOST")
	os.Unsetenv("WATCHPOST_PORT")
	t.Setenv("WATCHPOST_LISTEN", "127.0.0.1:9000")
	h, p, l, hs, ps, ls = listenerFlags()
	addr, err = resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:9000" {
		t.Fatalf("WATCHPOST_LISTEN = %q", addr)
	}
	// Legacy form combined with --host/--port must fail.
	os.Unsetenv("WATCHPOST_LISTEN")
	h2, p2, l2, hs2, ps2, ls2 := listenerFlags("--host", "127.0.0.1", "--port", "7402", "--listen", "127.0.0.1:8080")
	if _, err := resolveListener(h2, p2, l2, hs2, ps2, ls2); err == nil {
		t.Fatal("--listen combined with --host/--port accepted")
	}
}

func TestResolveListenerTrimsWhitespace(t *testing.T) {
	os.Unsetenv("WATCHPOST_LISTEN")
	h, p, l, hs, ps, ls := listenerFlags("--host", "  127.0.0.1  ", "--port", "  7402  ")
	host, port, err := resolveHostPort(h, p, hs, ps)
	if err != nil {
		t.Fatal(err)
	}
	if host != "127.0.0.1" || port != "7402" {
		t.Fatalf("cli trimmed host/port = %q/%q want 127.0.0.1/7402", host, port)
	}
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:7402" {
		t.Fatalf("cli listener = %q want 127.0.0.1:7402", addr)
	}
	t.Setenv("WATCHPOST_HOST", "  0.0.0.0  ")
	t.Setenv("WATCHPOST_PORT", "  7403  ")
	h, p, l, hs, ps, ls = listenerFlags()
	host, port, err = resolveHostPort(h, p, hs, ps)
	if err != nil {
		t.Fatal(err)
	}
	if host != "0.0.0.0" || port != "7403" {
		t.Fatalf("env trimmed host/port = %q/%q want 0.0.0.0/7403", host, port)
	}
	addr, err = resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "0.0.0.0:7403" {
		t.Fatalf("env listener = %q want 0.0.0.0:7403", addr)
	}
}

func TestResolveListenerWhitespaceOnlyFails(t *testing.T) {
	os.Unsetenv("WATCHPOST_LISTEN")
	h, p, l, hs, ps, ls := listenerFlags("--host", "   ", "--port", "   ")
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("whitespace-only --host/--port accepted")
	}
	t.Setenv("WATCHPOST_HOST", "   ")
	t.Setenv("WATCHPOST_PORT", "   ")
	h, p, l, hs, ps, ls = listenerFlags()
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("whitespace-only WATCHPOST_HOST/WATCHPOST_PORT accepted")
	}
	t.Setenv("WATCHPOST_HOST", "   ")
	t.Setenv("WATCHPOST_PORT", "7402")
	h, p, l, hs, ps, ls = listenerFlags()
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("whitespace-only host accepted with valid port")
	}
}

func TestValidatePort(t *testing.T) {
	for _, ok := range []string{"1", "7334", "65535"} {
		if err := validatePort(ok); err != nil {
			t.Fatalf("valid port %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "0", "-1", "65536", "7334.5", "x"} {
		if err := validatePort(bad); err == nil {
			t.Fatalf("invalid port %q accepted", bad)
		}
	}
}

func TestResolveListenerExplicitPortOverridesLegacyEnv(t *testing.T) {
	os.Unsetenv("WATCHPOST_HOST")
	os.Unsetenv("WATCHPOST_PORT")
	t.Setenv("WATCHPOST_LISTEN", "127.0.0.1:8080")
	h, p, l, hs, ps, ls := listenerFlags("--port", "7402")
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:7402" {
		t.Fatalf("explicit --port must override WATCHPOST_LISTEN: %q", addr)
	}
}

func TestResolveListenerExplicitHostOverridesLegacyEnv(t *testing.T) {
	os.Unsetenv("WATCHPOST_PORT")
	t.Setenv("WATCHPOST_LISTEN", "127.0.0.1:8080")
	t.Setenv("WATCHPOST_HOST", "0.0.0.0")
	h, p, l, hs, ps, ls := listenerFlags("--host", "10.0.0.1", "--port", "7402")
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "10.0.0.1:7402" {
		t.Fatalf("explicit --host/--port must override WATCHPOST_LISTEN: %q", addr)
	}
}

func TestResolveListenerExplicitListenOverridesHostPortEnv(t *testing.T) {
	t.Setenv("WATCHPOST_HOST", "0.0.0.0")
	t.Setenv("WATCHPOST_PORT", "9000")
	h, p, l, hs, ps, ls := listenerFlags("--listen", "127.0.0.1:8080")
	addr, err := resolveListener(h, p, l, hs, ps, ls)
	if err != nil {
		t.Fatal(err)
	}
	if addr != "127.0.0.1:8080" {
		t.Fatalf("explicit --listen must override host/port env: %q", addr)
	}
}

func TestResolveListenerEnvConflict(t *testing.T) {
	// Only environment variables involved: legacy WATCHPOST_LISTEN conflicts with
	// WATCHPOST_HOST or WATCHPOST_PORT and must fail rather than silently pick one.
	t.Setenv("WATCHPOST_LISTEN", "127.0.0.1:8080")
	t.Setenv("WATCHPOST_HOST", "0.0.0.0")
	h, p, l, hs, ps, ls := listenerFlags()
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("WATCHPOST_LISTEN + WATCHPOST_HOST conflict accepted")
	}
	os.Unsetenv("WATCHPOST_HOST")
	t.Setenv("WATCHPOST_PORT", "9000")
	if _, err := resolveListener(h, p, l, hs, ps, ls); err == nil {
		t.Fatal("WATCHPOST_LISTEN + WATCHPOST_PORT conflict accepted")
	}
}

func TestListenerOverrideSelected(t *testing.T) {
	fs := flag.NewFlagSet("test", flag.ContinueOnError)
	fs.String("host", "", "")
	fs.String("port", "", "")
	fs.String("listen", "", "")
	_ = fs.Parse(nil)
	os.Unsetenv("WATCHPOST_HOST")
	os.Unsetenv("WATCHPOST_PORT")
	os.Unsetenv("WATCHPOST_LISTEN")
	if listenerOverrideSelected(fs) {
		t.Fatal("bare invocation must not override durable config")
	}
	// WATCHPOST_LISTEN only: not an explicit new-form override.
	t.Setenv("WATCHPOST_LISTEN", "127.0.0.1:8080")
	if listenerOverrideSelected(fs) {
		t.Fatal("legacy WATCHPOST_LISTEN must not override durable config")
	}
	// WATCHPOST_HOST / WATCHPOST_PORT environment: override.
	os.Unsetenv("WATCHPOST_LISTEN")
	t.Setenv("WATCHPOST_HOST", "0.0.0.0")
	if !listenerOverrideSelected(fs) {
		t.Fatal("WATCHPOST_HOST must override durable config")
	}
	os.Unsetenv("WATCHPOST_HOST")
	t.Setenv("WATCHPOST_PORT", "7402")
	if !listenerOverrideSelected(fs) {
		t.Fatal("WATCHPOST_PORT must override durable config")
	}
	// Explicit CLI --host/--port: override.
	os.Unsetenv("WATCHPOST_PORT")
	_ = fs.Set("host", "127.0.0.1")
	_ = fs.Set("port", "7402")
	if !listenerOverrideSelected(fs) {
		t.Fatal("explicit --host/--port must override durable config")
	}
}

func TestValidateNoControlCmd(t *testing.T) {
	if err := validateNoControl("127.0.0.1:7402", "listen"); err != nil {
		t.Fatalf("valid listen rejected: %v", err)
	}
	for _, bad := range []string{"127.0.0.1:7402\nRestart=always", "a\x00b", "a\x0db"} {
		if err := validateNoControl(bad, "listen"); err == nil {
			t.Fatalf("control characters accepted: %q", bad)
		}
	}
}

// buildRuntimeFlags parses a foreground-style flag set (matching run()) so the
// durable-config override behaviour can be exercised end to end.
func buildRuntimeFlags(args ...string) *flag.FlagSet {
	fs := flag.NewFlagSet("watchpost", flag.ContinueOnError)
	fs.String("host", "", "")
	fs.String("port", "", "")
	fs.String("listen", "", "")
	fs.String("data-dir", "", "")
	fs.Bool("secure-cookies", false, "")
	_ = fs.Parse(args)
	return fs
}

func TestBuildRuntimeConfigDurableOverride(t *testing.T) {
	os.Unsetenv("WATCHPOST_LISTEN")
	t.Setenv("WATCHPOST_DATA_DIR", t.TempDir())
	t.Run("bare invocation keeps the durable default listener", func(t *testing.T) {
		os.Unsetenv("WATCHPOST_HOST")
		os.Unsetenv("WATCHPOST_PORT")
		fs := buildRuntimeFlags()
		cfg, err := buildRuntimeConfig(fs.Lookup("listen").Value.String(), fs.Lookup("host").Value.String(), fs.Lookup("port").Value.String(), fs.Lookup("data-dir").Value.String(), fs.Lookup("secure-cookies").Value.String() == "true", fs)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Listen != "127.0.0.1:7334" {
			t.Fatalf("default listener = %q want 127.0.0.1:7334", cfg.Listen)
		}
	})
	t.Run("legacy --listen keeps the durable listener", func(t *testing.T) {
		os.Unsetenv("WATCHPOST_HOST")
		os.Unsetenv("WATCHPOST_PORT")
		fs := buildRuntimeFlags("--listen", "127.0.0.1:8080")
		cfg, err := buildRuntimeConfig(fs.Lookup("listen").Value.String(), fs.Lookup("host").Value.String(), fs.Lookup("port").Value.String(), fs.Lookup("data-dir").Value.String(), fs.Lookup("secure-cookies").Value.String() == "true", fs)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Listen != "127.0.0.1:8080" {
			t.Fatalf("legacy listener = %q want 127.0.0.1:8080", cfg.Listen)
		}
	})
	t.Run("legacy WATCHPOST_LISTEN env keeps the durable listener", func(t *testing.T) {
		os.Unsetenv("WATCHPOST_HOST")
		os.Unsetenv("WATCHPOST_PORT")
		t.Setenv("WATCHPOST_LISTEN", "127.0.0.1:9000")
		fs := buildRuntimeFlags()
		cfg, err := buildRuntimeConfig(fs.Lookup("listen").Value.String(), fs.Lookup("host").Value.String(), fs.Lookup("port").Value.String(), fs.Lookup("data-dir").Value.String(), fs.Lookup("secure-cookies").Value.String() == "true", fs)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Listen != "127.0.0.1:9000" {
			t.Fatalf("env listener = %q want 127.0.0.1:9000", cfg.Listen)
		}
	})
	t.Run("explicit --host/--port override the durable config in memory", func(t *testing.T) {
		os.Unsetenv("WATCHPOST_HOST")
		os.Unsetenv("WATCHPOST_PORT")
		os.Unsetenv("WATCHPOST_LISTEN")
		fs := buildRuntimeFlags("--host", "0.0.0.0", "--port", "7404")
		cfg, err := buildRuntimeConfig(fs.Lookup("listen").Value.String(), fs.Lookup("host").Value.String(), fs.Lookup("port").Value.String(), fs.Lookup("data-dir").Value.String(), fs.Lookup("secure-cookies").Value.String() == "true", fs)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Listen != "0.0.0.0:7404" {
			t.Fatalf("explicit override listener = %q want 0.0.0.0:7404", cfg.Listen)
		}
	})
	t.Run("explicit --host/--port override a malformed legacy env", func(t *testing.T) {
		os.Unsetenv("WATCHPOST_HOST")
		os.Unsetenv("WATCHPOST_PORT")
		t.Setenv("WATCHPOST_LISTEN", "not-an-address")
		fs := buildRuntimeFlags("--host", "127.0.0.1", "--port", "7404")
		cfg, err := buildRuntimeConfig(fs.Lookup("listen").Value.String(), fs.Lookup("host").Value.String(), fs.Lookup("port").Value.String(), fs.Lookup("data-dir").Value.String(), fs.Lookup("secure-cookies").Value.String() == "true", fs)
		if err != nil {
			t.Fatalf("explicit override should beat malformed legacy env: %v", err)
		}
		if cfg.Listen != "127.0.0.1:7404" {
			t.Fatalf("explicit override listener = %q want 127.0.0.1:7404", cfg.Listen)
		}
	})
	t.Run("WATCHPOST_HOST/WATCHPOST_PORT env override the durable config", func(t *testing.T) {
		os.Unsetenv("WATCHPOST_LISTEN")
		t.Setenv("WATCHPOST_HOST", "10.0.0.7")
		t.Setenv("WATCHPOST_PORT", "7405")
		fs := buildRuntimeFlags()
		cfg, err := buildRuntimeConfig(fs.Lookup("listen").Value.String(), fs.Lookup("host").Value.String(), fs.Lookup("port").Value.String(), fs.Lookup("data-dir").Value.String(), fs.Lookup("secure-cookies").Value.String() == "true", fs)
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Listen != "10.0.0.7:7405" {
			t.Fatalf("env override listener = %q want 10.0.0.7:7405", cfg.Listen)
		}
	})
	t.Run("legacy env conflicting with host env fails clearly", func(t *testing.T) {
		t.Setenv("WATCHPOST_LISTEN", "127.0.0.1:8080")
		t.Setenv("WATCHPOST_HOST", "0.0.0.0")
		os.Unsetenv("WATCHPOST_PORT")
		fs := buildRuntimeFlags()
		if _, err := buildRuntimeConfig(fs.Lookup("listen").Value.String(), fs.Lookup("host").Value.String(), fs.Lookup("port").Value.String(), fs.Lookup("data-dir").Value.String(), fs.Lookup("secure-cookies").Value.String() == "true", fs); err == nil || !strings.Contains(err.Error(), "cannot be combined") {
			t.Fatalf("env conflict must fail clearly, got %v", err)
		}
	})
}

func TestInstallOptions(t *testing.T) {
	legacy, err := installOptions("/var/lib/watchpost", "127.0.0.1:8080", true, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if legacy.Listen != "127.0.0.1:8080" || legacy.Host != "" || legacy.Port != "" {
		t.Fatalf("legacy install options = %+v", legacy)
	}
	explicit, err := installOptions("/var/lib/watchpost", "0.0.0.0:7404", false, true, "/etc/watchpost/watchpost.env")
	if err != nil {
		t.Fatal(err)
	}
	if explicit.Host != "0.0.0.0" || explicit.Port != "7404" || explicit.SecureCookies != true || explicit.EnvFile != "/etc/watchpost/watchpost.env" {
		t.Fatalf("explicit install options = %+v", explicit)
	}
	ipv6, err := installOptions("/var/lib/watchpost", "[::1]:7404", false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if ipv6.Host != "::1" || ipv6.Port != "7404" {
		t.Fatalf("ipv6 install options = %+v", ipv6)
	}
	if _, err := installOptions("/var/lib/watchpost", "not-an-address", false, false, ""); err == nil {
		t.Fatal("un-splittable listener accepted")
	}
	// Options default to explicit mode when no legacy listen is set.
	def, err := installOptions("/var/lib/watchpost", "127.0.0.1:7334", false, false, "")
	if err != nil {
		t.Fatal(err)
	}
	if def.Host != "127.0.0.1" || def.Port != "7334" || def.Listen != "" {
		t.Fatalf("default install options = %+v", def)
	}
}
