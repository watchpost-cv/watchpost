package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/watchpost-ops/watchpost/internal/config"
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
