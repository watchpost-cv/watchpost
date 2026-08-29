package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/watchpost-ops/watchpost/internal/config"
	"github.com/watchpost-ops/watchpost/internal/hostcollector"
	"github.com/watchpost-ops/watchpost/internal/server"
	"github.com/watchpost-ops/watchpost/internal/store"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "watchpost:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) > 0 && args[0] == "collector" && len(args) == 2 && args[1] == "sample" {
		// Host diagnostics from the canonical sampler; the bundled collector
		// lifecycle was removed (see R17). The separate watchpost-agent is the
		// supported host-monitoring delivery program.
		return runCollectorSample()
	}
	if len(args) == 1 && (args[0] == "--version" || args[0] == "version") {
		fmt.Fprintln(os.Stdout, version)
		return nil
	}
	// Serving is Watchpost's primary operation, matching Warden, Cortex, and
	// Trestle: a built binary starts with ./watchpost. Keep `serve` as a
	// backwards-compatible alias for scripts written during early development.
	if len(args) > 0 && args[0] == "serve" {
		args = args[1:]
	}
	fs := flag.NewFlagSet("watchpost", flag.ContinueOnError)
	listen := fs.String("listen", "", "listen address (overrides WATCHPOST_LISTEN)")
	dataDir := fs.String("data-dir", "", "data directory (overrides WATCHPOST_DATA_DIR)")
	secureCookies := fs.Bool("secure-cookies", false, "mark session cookies Secure behind an HTTPS reverse proxy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: watchpost [options]")
	}
	cfg, err := config.Load(config.Overrides{Listen: *listen, DataDir: *dataDir, SecureCookies: *secureCookies})
	if err != nil {
		return err
	}
	logger := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	database, err := store.Open(context.Background(), cfg.DataDir)
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer database.Close()
	app := server.New(cfg, version, logger, database)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return app.Run(ctx)
}

func runCollectorSample() error {
	samples, err := hostcollector.New().Sample(context.Background(), 250*time.Millisecond)
	if err != nil {
		return fmt.Errorf("sample host: %w", err)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(map[string]any{"version": 1, "samples": samples})
}