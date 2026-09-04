package main

import (
	"io"
	"os"
	"strings"
	"testing"
)

// captureStderr runs f while capturing os.Stderr, returning the captured text
// and f's result.
func captureStderr(t *testing.T, f func() int) (string, int) {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	code := f()
	_ = w.Close()
	os.Stderr = old
	out, _ := io.ReadAll(r)
	return string(out), code
}

func TestRunServiceInstallUsageErrors(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"malformed port", []string{"install", "--port", "abc"}, "port must be an integer"},
		{"oversized port", []string{"install", "--port", "65536"}, "65535"},
		{"zero port", []string{"install", "--port", "0"}, "port must be an integer"},
		{"listen combined with host/port", []string{"install", "--host", "127.0.0.1", "--port", "7404", "--listen", "127.0.0.1:8080"}, "--listen cannot be combined"},
		{"unknown flag", []string{"install", "--bogus"}, "unknown flag"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, code := captureStderr(t, func() int { return runService(tc.args) })
			if code != 2 {
				t.Fatalf("exit = %d want 2; output: %s", code, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Fatalf("output %q missing %q", out, tc.want)
			}
		})
	}
}

func TestRunServiceInstallValidFlagsReachRootCheck(t *testing.T) {
	out, code := captureStderr(t, func() int { return runService([]string{"install", "--host", "127.0.0.1", "--port", "7404"}) })
	// The canonical example passes listener validation and proceeds to the
	// operational root requirement.
	if code != 1 {
		t.Fatalf("exit = %d want 1 (requires root); output: %s", code, out)
	}
	if !strings.Contains(out, "requires root") {
		t.Fatalf("output %q missing root requirement", out)
	}
}

func TestServiceLifecycleSuccessGrammar(t *testing.T) {
	want := map[string]string{
		"start":   "watchpost.service started.",
		"stop":    "watchpost.service stopped.",
		"restart": "watchpost.service restarted.",
		"enable":  "watchpost.service enabled.",
		"disable": "watchpost.service disabled.",
	}
	for verb, expected := range want {
		if got := serviceLifecycleSuccess(verb); got != expected {
			t.Fatalf("%s message = %q, want %q", verb, got, expected)
		}
	}
}

func TestRunServiceLegacyInstallFlagsReachRootCheck(t *testing.T) {
	out, code := captureStderr(t, func() int { return runService([]string{"install", "--listen", "127.0.0.1:8080"}) })
	if code != 1 {
		t.Fatalf("exit = %d want 1 (requires root); output: %s", code, out)
	}
	if !strings.Contains(out, "requires root") {
		t.Fatalf("output %q missing root requirement", out)
	}
}

func TestRunServiceUnknownCommand(t *testing.T) {
	out, code := captureStderr(t, func() int { return runService([]string{"bogus"}) })
	if code != 2 {
		t.Fatalf("exit = %d want 2; output: %s", code, out)
	}
	if !strings.Contains(out, "unknown service command") {
		t.Fatalf("output %q missing unknown command message", out)
	}
}

func TestRunServiceRejectsFlagsForNonInstallCommands(t *testing.T) {
	out, code := captureStderr(t, func() int { return runService([]string{"start", "--host", "127.0.0.1", "--port", "7404"}) })
	if code != 2 {
		t.Fatalf("exit = %d want 2; output: %s", code, out)
	}
	if !strings.Contains(out, "no flags are accepted") {
		t.Fatalf("output %q missing no-flags message", out)
	}
}

func TestRunServiceUpdateTakesPositionals(t *testing.T) {
	out, code := captureStderr(t, func() int { return runService([]string{"update"}) })
	if code != 2 {
		t.Fatalf("exit = %d want 2; output: %s", code, out)
	}
	if !strings.Contains(out, "usage: watchpost service update ARTIFACT SHA256") {
		t.Fatalf("output %q missing update usage", out)
	}
}
