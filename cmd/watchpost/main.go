package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/watchpost-ops/watchpost/internal/collectorclient"
	"github.com/watchpost-ops/watchpost/internal/collectorcontract"
	"github.com/watchpost-ops/watchpost/internal/collectorservice"
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
	if len(args) > 0 && args[0] == "run" {
		return runCollectorLoop(args[1:])
	}
	if len(args) > 0 && map[string]bool{"install": true, "status": true, "logs": true, "uninstall": true}[args[0]] {
		action := args[0]
		fs := flag.NewFlagSet("watchpost collector "+action, flag.ContinueOnError)
		system := fs.Bool("system", false, "manage a system-wide collector service")
		configPath := fs.String("config", "", "collector configuration path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if fs.NArg() != 0 {
			return fmt.Errorf("unexpected collector arguments")
		}
		paths, err := collectorservice.Resolve(*system, *configPath)
		if err != nil {
			return err
		}
		manager := collectorservice.New()
		switch action {
		case "install":
			executable, err := os.Executable()
			if err != nil {
				return err
			}
			return manager.Install(executable, paths)
		case "status":
			return manager.Status(paths)
		case "logs":
			return manager.Logs(paths)
		case "uninstall":
			return manager.Uninstall(paths)
		}
	}
	return fmt.Errorf("usage: watchpost collector {sample|pair|run|install|status|logs|uninstall}")
}

func runCollectorLoop(args []string) error {
	fs := flag.NewFlagSet("watchpost collector run", flag.ContinueOnError)
	configPath := fs.String("config", defaultCollectorConfig(), "collector configuration path")
	statePath := fs.String("state", "", "durable queue state path")
	interval := fs.Duration("interval", time.Minute, "sampling interval")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *interval < time.Second {
		return errors.New("invalid collector run options")
	}
	config, err := collectorclient.Load(*configPath)
	if err != nil {
		return fmt.Errorf("load collector config: %w", err)
	}
	if *statePath == "" {
		*statePath = filepath.Join(filepath.Dir(*configPath), "collector-queue.json")
	}
	queue, err := collectorclient.OpenQueue(*statePath, 256, 8<<20)
	if err != nil {
		return fmt.Errorf("open collector queue: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	sampler := hostcollector.New()
	sender := collectorclient.Sender{}
	var retryTimer *time.Timer
	var retry <-chan time.Time
	backoff := time.Second
	schedule := func(delay time.Duration) {
		if retryTimer != nil {
			retryTimer.Stop()
		}
		retryTimer = time.NewTimer(delay)
		retry = retryTimer.C
	}
	sample := func() error {
		samples, sampleErr := sampler.Sample(ctx, 250*time.Millisecond)
		if sampleErr != nil {
			return sampleErr
		}
		if queue.DroppedSamples() > 0 {
			dropped := float64(queue.DroppedSamples())
			samples = append(samples, collectorcontract.Sample{ObservedAt: time.Now().UTC(), Signal: "collector.dropped_samples", Value: &dropped, Unit: "samples", Quality: "bad", Labels: map[string]string{}})
		}
		if enqueueErr := queue.Enqueue(config, samples, time.Now().UTC()); enqueueErr != nil {
			fmt.Fprintln(os.Stderr, "watchpost collector:", enqueueErr)
		}
		if retryTimer == nil && queue.Pending() > 0 {
			schedule(0)
		}
		return nil
	}
	if err = sample(); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err = sample(); err != nil {
				return err
			}
		case <-retry:
			retryTimer = nil
			retry = nil
			if err = collectorclient.Drain(ctx, sender, config, queue); err != nil {
				jitter := time.Duration(rand.Int64N(max(int64(backoff/2), 1)))
				fmt.Fprintf(os.Stderr, "watchpost collector: delivery failed: %v; retrying\n", err)
				schedule(backoff + jitter)
				backoff = min(backoff*2, 5*time.Minute)
			} else {
				backoff = time.Second
			}
		}
	}
}

func defaultCollectorConfig() string {
	directory, err := os.UserConfigDir()
	if err != nil {
		return "collector.json"
	}
	return directory + string(os.PathSeparator) + "watchpost" + string(os.PathSeparator) + "collector.json"
}
