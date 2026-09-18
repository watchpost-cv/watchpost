package main

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/watchpost-cv/watchpost/internal/auth"
	"github.com/watchpost-cv/watchpost/internal/backup"
	"github.com/watchpost-cv/watchpost/internal/config"
	"github.com/watchpost-cv/watchpost/internal/service"
	"github.com/watchpost-cv/watchpost/internal/store"
)

func controlConfig(data string) (config.Config, error) {
	return config.Load(config.Overrides{DataDir: data})
}

// resolveDataDir applies the canonical instance-resolution precedence shared by
// setup/config/reset: an explicit --data-dir wins, then WATCHPOST_DATA_DIR,
// then the data directory recorded by the installed managed service, then the
// normal default. It fails closed rather than silently targeting a different
// instance when the installed unit exists but cannot be used safely.
func resolveInstanceDataDir(fs *flag.FlagSet, explicit string) (string, error) {
	dir := strings.TrimSpace(explicit)
	if dir == "" && strings.TrimSpace(os.Getenv("WATCHPOST_DATA_DIR")) == "" {
		installedData, installed, installedErr := service.InstalledDataDir()
		if installedErr != nil {
			return "", installedErr
		}
		if installed {
			dir = installedData
		}
	}
	return dir, nil
}

func runSetup(args []string) error {
	fs := flag.NewFlagSet("watchpost setup", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	data := fs.String("data-dir", "", "data directory")
	email := fs.String("email", "", "administrator email")
	emailFile := fs.String("email-file", "", "file containing administrator email")
	username := fs.String("username", "", "administrator username")
	passwordFile := fs.String("password-file", "", "file containing password")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || *passwordFile == "" {
		return fmt.Errorf("usage: watchpost setup (--email ADDRESS|--email-file FILE) --username NAME --password-file FILE [--data-dir DIR]")
	}
	if *emailFile != "" {
		raw, err := os.ReadFile(*emailFile)
		if err != nil {
			return err
		}
		*email = strings.TrimSpace(string(raw))
	}
	if *email == "" {
		return fmt.Errorf("--email or --email-file is required")
	}
	password, err := os.ReadFile(*passwordFile)
	if err != nil {
		return err
	}
	resolved, err := resolveInstanceDataDir(fs, *data)
	if err != nil {
		return err
	}
	cfg, err := controlConfig(resolved)
	if err != nil {
		return err
	}
	db, err := store.Open(context.Background(), cfg.DataDir)
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = auth.New(db).Setup(context.Background(), *username, *email, strings.TrimRight(string(password), "\r\n"), "")
	if err == nil {
		fmt.Println("Watchpost administrator configured.")
	}
	return err
}

func runConfig(args []string) error {
	fs := flag.NewFlagSet("watchpost config", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	data := fs.String("data-dir", "", "data directory")
	jsonOut := fs.Bool("json", false, "machine-readable output")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 || fs.Arg(0) != "show" {
		return fmt.Errorf("usage: watchpost config show [--data-dir DIR] [--json]")
	}
	resolved, err := resolveInstanceDataDir(fs, *data)
	if err != nil {
		return err
	}
	cfg, err := controlConfig(resolved)
	if err != nil {
		return err
	}
	if *jsonOut {
		return json.NewEncoder(os.Stdout).Encode(map[string]any{"project": "watchpost", "dataDir": cfg.DataDir, "listen": cfg.Listen, "secureCookies": cfg.SecureCookies})
	}
	fmt.Printf("Data directory: %s\nListen: %s\n", cfg.DataDir, cfg.Listen)
	return nil
}

func runReset(args []string) error {
	fs := flag.NewFlagSet("watchpost reset", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	auth := fs.Bool("auth", false, "reset accounts, sessions and user-attributed records (conversations, action requests)")
	all := fs.Bool("all", false, "reset all Watchpost state")
	data := fs.String("data-dir", "", "data directory")
	confirm := fs.String("confirm", "", "non-interactive confirmation")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 || (*auth == *all) {
		return fmt.Errorf("usage: watchpost reset (--auth|--all) [--data-dir DIR] [--confirm 'WATCHPOST AUTH|WATCHPOST ALL']\n\nNOTE: --auth clears accounts and sessions AND the user-attributed operational\nrecords tied to them (conversations, action requests). It does not touch posts,\nrules, observations or evidence.")
	}
	resolvedData, err := resolveInstanceDataDir(fs, *data)
	if err != nil {
		return err
	}
	cfg, err := controlConfig(resolvedData)
	if err != nil {
		return err
	}
	mode := "AUTH"
	if *all {
		mode = "ALL"
	}
	want := "WATCHPOST " + mode
	if !confirmWatchpost(want, *confirm) {
		return fmt.Errorf("confirmation did not match; nothing changed")
	}
	stamp := time.Now().UTC().Format("20060102T150405Z")
	if *all {
		if _, err = os.Stat(cfg.DataDir); os.IsNotExist(err) {
			return nil
		}
		if err = os.Rename(cfg.DataDir, cfg.DataDir+".reset-"+stamp); err != nil {
			return fmt.Errorf("back up data directory: %w", err)
		}
		if err = os.MkdirAll(cfg.DataDir, 0700); err != nil {
			return err
		}
	} else {
		db, openErr := store.Open(context.Background(), cfg.DataDir)
		if openErr != nil {
			return openErr
		}
		defer db.Close()
		backupPath := cfg.DataDir + "/reset-auth-" + stamp + ".db"
		if err = backup.Create(context.Background(), db, backupPath, ""); err != nil {
			return fmt.Errorf("back up database: %w", err)
		}
		tx, beginErr := db.DB.BeginTx(context.Background(), nil)
		if beginErr != nil {
			return beginErr
		}
		defer tx.Rollback()
		for _, q := range []string{"DELETE FROM action_requests", "DELETE FROM conversations", "UPDATE audit SET actor_user_id=NULL", "DELETE FROM sessions", "DELETE FROM users"} {
			if _, err = tx.Exec(q); err != nil {
				return err
			}
		}
		if err = tx.Commit(); err != nil {
			return err
		}
	}
	fmt.Printf("Watchpost %s reset complete. A timestamped backup was retained.\n", strings.ToLower(mode))
	return nil
}

func confirmWatchpost(want, supplied string) bool {
	if supplied != "" {
		return supplied == want
	}
	description := "all Watchpost state"
	if want == "WATCHPOST AUTH" {
		description = "accounts, sessions and user-attributed records (conversations, action requests); posts, rules, observations and evidence are preserved"
	}
	fmt.Fprintf(os.Stderr, "This will reset %s.\nType %q to continue: ", description, want)
	got, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	return strings.TrimSpace(got) == want
}
