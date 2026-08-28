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

	"github.com/watchpost-ops/watchpost/internal/collectorclient"
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
	if len(args) > 0 && args[0] == "collector" {
		return runCollector(args[1:])
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
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: watchpost [options]")
	}
	cfg, err := config.Load(config.Overrides{Listen: *listen, DataDir: *dataDir})
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

func runCollector(args []string) error {
	if len(args) == 1 && args[0] == "sample" {
		samples, err := hostcollector.New().Sample(context.Background(), 250*time.Millisecond)
		if err != nil {
			return fmt.Errorf("sample host: %w", err)
		}
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(map[string]any{"version": 1, "samples": samples})
	}
	if len(args) > 0 && args[0] == "pair" {
		fs := flag.NewFlagSet("watchpost collector pair", flag.ContinueOnError)
		serverURL := fs.String("server", "", "Watchpost server URL")
		token := fs.String("token", "", "one-use pairing token")
		hostname, _ := os.Hostname()
		collectorID := fs.String("id", hostname, "collector identity")
		configPath := fs.String("config", defaultCollectorConfig(), "collector configuration path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 || *serverURL == "" || *token == "" || *collectorID == "" {
			return fmt.Errorf("usage: watchpost collector pair --server URL --token TOKEN [--id ID] [--config PATH]")
		}
		config, err := collectorclient.Pair(*serverURL, *token, *collectorID, *configPath, nil)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Paired collector %s with post %s.\nConfiguration: %s\n", config.CollectorID, config.PostID, *configPath)
		return nil
	}
	return fmt.Errorf("usage: watchpost collector {sample|pair}")
}

func defaultCollectorConfig() string {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "collector.json"
	}
	return directory + string(os.PathSeparator) + "watchpost" + string(os.PathSeparator) + "collector.json"
}
