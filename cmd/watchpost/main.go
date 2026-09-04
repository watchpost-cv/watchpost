package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/watchpost-cv/watchpost/internal/backup"
	"github.com/watchpost-cv/watchpost/internal/config"
	"github.com/watchpost-cv/watchpost/internal/devices"
	"github.com/watchpost-cv/watchpost/internal/hostcollector"
	"github.com/watchpost-cv/watchpost/internal/server"
	"github.com/watchpost-cv/watchpost/internal/service"
	"github.com/watchpost-cv/watchpost/internal/store"
)

var version = "0.1.0"

func main() {
	// Service-management commands must remain usable even when the application
	// configuration is unhealthy, so dispatch before any runtime config load.
	if len(os.Args) > 1 && os.Args[1] == "service" {
		os.Exit(runService(os.Args[2:]))
	}
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
	if len(args) > 0 && (args[0] == "backup" || args[0] == "restore" || args[0] == "rekey") {
		return runOpsCommand(args[0], args[1:])
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
	host := fs.String("host", "", "HTTP bind host (default 127.0.0.1; WATCHPOST_HOST overrides, CLI wins)")
	port := fs.String("port", "", "HTTP bind port, 1-65535 (default 7334; WATCHPOST_PORT overrides, CLI wins)")
	listen := fs.String("listen", "", "listen address (legacy; alternative to --host/--port, honors WATCHPOST_LISTEN)")
	dataDir := fs.String("data-dir", "", "data directory (overrides WATCHPOST_DATA_DIR)")
	secureCookies := fs.Bool("secure-cookies", false, "mark session cookies Secure behind an HTTPS reverse proxy")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("usage: watchpost [options]")
	}
	cfg, err := buildRuntimeConfig(*listen, *host, *port, *dataDir, *secureCookies, fs)
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
	if err := app.Run(ctx); err != nil {
		return fmt.Errorf("%v (listener: %s)", err, cfg.Listen)
	}
	return nil
}

// buildRuntimeConfig resolves the listener flags and environment and produces
// the runtime configuration, applying the explicit host/port override to the
// durable config listener in memory so the advertised override genuinely
// controls the runtime listener. Bare invocations and legacy --listen keep the
// durable config listener.
func buildRuntimeConfig(listen, host, port, dataDir string, secureCookies bool, fs *flag.FlagSet) (config.Config, error) {
	addr, err := resolveListener(host, port, listen, flagProvided(fs, "host"), flagProvided(fs, "port"), flagProvided(fs, "listen"))
	if err != nil {
		return config.Config{}, err
	}
	overrides := config.Overrides{DataDir: dataDir, SecureCookies: secureCookies}
	if listenerOverrideSelected(fs) {
		overrides.Listen = addr
	} else {
		overrides.Listen = listen
	}
	return config.Load(overrides)
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

// runOpsCommand dispatches backup, restore and rekey. These operations are
// deliberately separate from the serving process; restore and rekey require
// the node to be stopped.
func runOpsCommand(action string, arguments []string) error {
	fs := flag.NewFlagSet("watchpost "+action, flag.ContinueOnError)
	output := fs.String("output", "", "backup output path")
	input := fs.String("input", "", "restore input path")
	dataDir := fs.String("data-dir", "", "data directory (default from WATCHPOST_DATA_DIR or user config)")
	passphraseFile := fs.String("passphrase-file", "", "file containing the backup passphrase")
	force := fs.Bool("force", false, "replace an existing database on restore")
	oldKeyFile := fs.String("old-key-file", "", "old installation master key file")
	newKeyFile := fs.String("new-key-file", "", "new installation master key file")
	keyEnv := fs.String("key-env", "WATCHPOST_MASTER_KEY", "environment variable holding the master key")
	if err := fs.Parse(arguments); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected arguments")
	}
	dir, err := resolveDataDir(*dataDir)
	if err != nil {
		return err
	}
	passphrase, err := readOptionalFile(*passphraseFile)
	if err != nil {
		return err
	}
	switch action {
	case "backup":
		if *output == "" {
			return fmt.Errorf("backup requires --output")
		}
		database, err := store.Open(context.Background(), dir)
		if err != nil {
			return err
		}
		defer database.Close()
		if err := backup.Create(context.Background(), database, *output, passphrase); err != nil {
			return err
		}
		if passphrase != "" {
			fmt.Fprintf(os.Stdout, "Encrypted backup written to %s\n", *output)
		} else {
			fmt.Fprintf(os.Stdout, "Backup written to %s\n", *output)
		}
		return nil
	case "restore":
		if *input == "" {
			return fmt.Errorf("restore requires --input")
		}
		if err := backup.Restore(context.Background(), dir, *input, passphrase, *force); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Database restored to %s\n", dir)
		return nil
	case "rekey":
		oldKey, err := readKey(*oldKeyFile, os.Getenv(*keyEnv))
		if err != nil {
			return fmt.Errorf("old master key: %w", err)
		}
		newKey, err := readKey(*newKeyFile, os.Getenv("WATCHPOST_MASTER_KEY_NEW"))
		if err != nil {
			return fmt.Errorf("new master key: %w", err)
		}
		database, err := store.Open(context.Background(), dir)
		if err != nil {
			return err
		}
		defer database.Close()
		count, err := devices.RekeyCredentials(context.Background(), database, oldKey, newKey)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "Re-encrypted %d credential sets with the new master key\n", count)
		return nil
	}
	return fmt.Errorf("unknown operation")
}

func resolveDataDir(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	cfg, err := config.Load(config.Overrides{})
	if err != nil {
		return "", err
	}
	return cfg.DataDir, nil
}

func readOptionalFile(path string) (string, error) {
	if path == "" {
		return "", nil
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(content), "\r\n"), nil
}

func readKey(file, env string) (string, error) {
	if file != "" {
		return readOptionalFile(file)
	}
	if env != "" {
		return strings.TrimRight(env, "\r\n"), nil
	}
	return "", fmt.Errorf("not provided")
}

// runService dispatches `watchpost service <command>` operating the Watchpost
// systemd **system** unit. Exit codes: 0 success, 1 operational failure, 2
// usage error (canonical Web Fleet convention).
func runService(args []string) int {
	cmd := "status"
	// Flags that consume a following value are recorded as pairs so their value
	// is never misclassified as a positional argument.
	valueFlags := map[string]bool{"--data": true, "--data-dir": true, "--host": true, "--port": true, "--listen": true, "--env-file": true}
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a != "" && !strings.HasPrefix(a, "-") {
			if cmd == "status" && len(positional) == 0 {
				cmd = a
				continue
			}
			positional = append(positional, a)
			continue
		}
		flags = append(flags, a)
		if valueFlags[a] && i+1 < len(args) {
			i++
			flags = append(flags, args[i])
		}
	}
	usage := func(msg string) int {
		fmt.Fprintf(os.Stderr, "watchpost service %s: %s\n", cmd, msg)
		return 2
	}
	if len(flags) > 0 {
		switch cmd {
		case "install":
			for i := 0; i < len(flags); i++ {
				switch flags[i] {
				case "--data", "--data-dir":
					if i+1 < len(flags) {
						i++
					} else {
						return usage("--data requires a path")
					}
				case "--host":
					if i+1 < len(flags) {
						i++
					} else {
						return usage("--host requires an address")
					}
				case "--port":
					if i+1 < len(flags) {
						i++
					} else {
						return usage("--port requires a number")
					}
				case "--listen":
					if i+1 < len(flags) {
						i++
					} else {
						return usage("--listen requires an address")
					}
				case "--env-file":
					if i+1 < len(flags) {
						i++
					} else {
						return usage("--env-file requires a path")
					}
				case "--secure-cookies":
				default:
					return usage("unknown flag " + flags[i])
				}
			}
		case "logs":
			if len(flags) > 1 || flags[0] != "--follow" {
				return usage("logs accepts only --follow")
			}
		default:
			return usage("no flags are accepted for " + cmd)
		}
	}
	switch cmd {
	case "install":
		if len(positional) != 0 {
			return usage("install takes no positional arguments")
		}
		data := service.DefaultDataDir
		listen, host, port := "", "", ""
		hostSet, portSet, listenSet := false, false, false
		envfile, secureCookies := "", false
		for i := 0; i < len(flags); i++ {
			switch flags[i] {
			case "--data", "--data-dir":
				if i+1 < len(flags) {
					i++
					data = flags[i]
				}
			case "--host":
				if i+1 < len(flags) {
					i++
					host = flags[i]
					hostSet = true
				}
			case "--port":
				if i+1 < len(flags) {
					i++
					port = flags[i]
					portSet = true
				}
			case "--listen":
				if i+1 < len(flags) {
					i++
					listen = flags[i]
					listenSet = true
				}
			case "--env-file":
				if i+1 < len(flags) {
					i++
					envfile = flags[i]
				}
			case "--secure-cookies":
				secureCookies = true
			}
		}
		addr, err := resolveListener(host, port, listen, hostSet, portSet, listenSet)
		if err != nil {
			fmt.Fprintln(os.Stderr, "watchpost service install:", err)
			return 2
		}
		if err := validateNoControl(addr, "listen"); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost service install:", err)
			return 2
		}
		// Resolve the recorded listener and its mode (explicit host/port vs
		// legacy --listen/WATCHPOST_LISTEN bootstrap) for the generated unit.
		legacy := listenSet
		if !legacy {
			if _, hasListen := os.LookupEnv("WATCHPOST_LISTEN"); hasListen && !hostSet && !portSet {
				legacy = true
			}
		}
		opts, err := installOptions(data, addr, legacy, secureCookies, envfile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "watchpost service install:", err)
			return 2
		}
		if err := service.InstallOptions(service.Executable(), opts); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost service install:", err)
			return 1
		}
		fmt.Fprintln(os.Stdout, "watchpost.service installed.")
		return 0
	case "uninstall":
		if len(positional) != 0 {
			return usage("uninstall takes no positional arguments")
		}
		if err := service.Uninstall(); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost service uninstall:", err)
			return 1
		}
		fmt.Fprintln(os.Stdout, "watchpost.service uninstalled. Data in "+service.DefaultDataDir+" was preserved.")
		return 0
	case "start", "stop", "restart", "enable", "disable":
		if len(positional) != 0 {
			return usage(cmd + " takes no positional arguments")
		}
		if err := lifecycleErr(cmd); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost service "+cmd+":", err)
			return 1
		}
		fmt.Fprintln(os.Stdout, serviceLifecycleSuccess(cmd))
		return 0
	case "status":
		if len(positional) != 0 {
			return usage("status takes no positional arguments")
		}
		if err := service.Status(os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost service status:", err)
			return 1
		}
		return 0
	case "logs":
		if len(positional) != 0 {
			return usage("logs takes no positional arguments")
		}
		follow := len(flags) > 0 && flags[0] == "--follow"
		if err := service.Logs(follow, os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost service logs:", err)
			return 1
		}
		return 0
	case "update":
		if len(positional) != 2 {
			return usage("usage: watchpost service update ARTIFACT SHA256")
		}
		if err := service.Update(positional[0], positional[1]); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost service update:", err)
			return 1
		}
		fmt.Fprintln(os.Stdout, "watchpost.service updated.")
		return 0
	case "rollback":
		if len(positional) != 0 {
			return usage("rollback takes no positional arguments")
		}
		if err := service.Rollback(); err != nil {
			fmt.Fprintln(os.Stderr, "watchpost service rollback:", err)
			return 1
		}
		fmt.Fprintln(os.Stdout, "watchpost.service rolled back.")
		return 0
	default:
		fmt.Fprintf(os.Stderr, "watchpost: unknown service command %q\n\nUsage: watchpost service <install|uninstall|start|stop|restart|status|enable|disable|logs|update|rollback> [flags]\n", cmd)
		return 2
	}
}

func serviceLifecycleSuccess(verb string) string {
	words := map[string]string{
		"start": "started", "stop": "stopped", "restart": "restarted",
		"enable": "enabled", "disable": "disabled",
	}
	return "watchpost.service " + words[verb] + "."
}

func lifecycleErr(verb string) error {
	switch verb {
	case "start":
		return service.Start()
	case "stop":
		return service.Stop()
	case "restart":
		return service.Restart()
	case "enable":
		return service.Enable()
	case "disable":
		return service.Disable()
	}
	return fmt.Errorf("unknown lifecycle verb")
}

// installOptions builds the service.Options recorded in a newly installed unit
// from the resolved listener. Legacy bootstrap units keep the single-address
// --listen form; explicit host/port units are split back into --host/--port so
// their recorded listener is the runtime listener across restart and reboot.
func installOptions(dataDir, addr string, legacy bool, secureCookies bool, envfile string) (service.Options, error) {
	if legacy {
		return service.Options{DataDir: dataDir, Listen: addr, SecureCookies: secureCookies, EnvFile: envfile}, nil
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return service.Options{}, fmt.Errorf("cannot split resolved listener %q: %w", addr, err)
	}
	return service.Options{DataDir: dataDir, Host: host, Port: port, SecureCookies: secureCookies, EnvFile: envfile}, nil
}
