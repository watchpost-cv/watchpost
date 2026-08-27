package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
)

const DefaultListen = "127.0.0.1:8080"

type Config struct {
	Listen  string
	DataDir string
}

type Overrides struct {
	Listen  string
	DataDir string
}

func Load(overrides Overrides) (Config, error) {
	cfg := Config{Listen: DefaultListen}
	if dir, err := os.UserConfigDir(); err == nil {
		cfg.DataDir = filepath.Join(dir, "watchpost")
	} else {
		return Config{}, fmt.Errorf("resolve user config directory: %w", err)
	}
	if value := os.Getenv("WATCHPOST_LISTEN"); value != "" {
		cfg.Listen = value
	}
	if value := os.Getenv("WATCHPOST_DATA_DIR"); value != "" {
		cfg.DataDir = value
	}
	if overrides.Listen != "" {
		cfg.Listen = overrides.Listen
	}
	if overrides.DataDir != "" {
		cfg.DataDir = overrides.DataDir
	}
	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func validate(cfg Config) error {
	if _, _, err := net.SplitHostPort(cfg.Listen); err != nil {
		return fmt.Errorf("invalid listen address %q: %w", cfg.Listen, err)
	}
	if !filepath.IsAbs(cfg.DataDir) {
		return fmt.Errorf("data directory must be absolute")
	}
	return nil
}
