package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const DefaultListen = "127.0.0.1:8080"

type Config struct {
	Listen        string
	DataDir       string
	SecureCookies bool
	Retention     Retention
}

// Retention holds the deterministic pruning policy applied by the retention
// worker. A zero duration disables pruning for that category. Batch bounds the
// rows removed by a single DELETE so long passes do not monopolise the
// database connection or grow the WAL unboundedly.
type Retention struct {
	Observations     time.Duration
	CheckResults     time.Duration
	Logs             time.Duration
	Changes          time.Duration
	AlertsResolved   time.Duration
	Deliveries       time.Duration
	PairingTokens    time.Duration
	PairingRequests  time.Duration
	FederationInbox  time.Duration
	FederationOutbox time.Duration
	Conversations    time.Duration
	Interval         time.Duration
	Batch            int
}

func DefaultRetention() Retention {
	return Retention{
		Observations:     30 * 24 * time.Hour,
		CheckResults:     90 * 24 * time.Hour,
		Logs:             30 * 24 * time.Hour,
		Changes:          2 * 365 * 24 * time.Hour,
		AlertsResolved:   365 * 24 * time.Hour,
		Deliveries:       30 * 24 * time.Hour,
		PairingTokens:    7 * 24 * time.Hour,
		PairingRequests:  7 * 24 * time.Hour,
		FederationInbox:  7 * 24 * time.Hour,
		FederationOutbox: 30 * 24 * time.Hour,
		Conversations:    180 * 24 * time.Hour,
		Interval:         time.Hour,
		Batch:            1000,
	}
}

type Overrides struct {
	Listen        string
	DataDir       string
	SecureCookies bool
}

func Load(overrides Overrides) (Config, error) {
	cfg := Config{Listen: DefaultListen, Retention: DefaultRetention()}
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
	if value := os.Getenv("WATCHPOST_SECURE_COOKIES"); value == "1" || value == "true" {
		cfg.SecureCookies = true
	}
	if overrides.Listen != "" {
		cfg.Listen = overrides.Listen
	}
	if overrides.DataDir != "" {
		cfg.DataDir = overrides.DataDir
	}
	if overrides.SecureCookies {
		cfg.SecureCookies = true
	}
	if err := applyRetentionEnv(&cfg); err != nil {
		return Config{}, err
	}
	if err := validate(cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func applyRetentionEnv(cfg *Config) error {
	r := &cfg.Retention
	set := func(target *time.Duration, name string) error {
		value := os.Getenv("WATCHPOST_RETENTION_" + name)
		if value == "" {
			return nil
		}
		duration, err := ParseRetentionDuration(value)
		if err != nil {
			return fmt.Errorf("WATCHPOST_RETENTION_%s: %w", name, err)
		}
		*target = duration
		return nil
	}
	for name, target := range map[string]*time.Duration{
		"OBSERVATIONS":      &r.Observations,
		"CHECK_RESULTS":     &r.CheckResults,
		"LOGS":              &r.Logs,
		"CHANGES":           &r.Changes,
		"ALERTS_RESOLVED":   &r.AlertsResolved,
		"DELIVERIES":        &r.Deliveries,
		"PAIRING_TOKENS":    &r.PairingTokens,
		"PAIRING_REQUESTS":  &r.PairingRequests,
		"FEDERATION_INBOX":  &r.FederationInbox,
		"FEDERATION_OUTBOX": &r.FederationOutbox,
		"CONVERSATIONS":     &r.Conversations,
		"INTERVAL":          &r.Interval,
	} {
		if err := set(target, name); err != nil {
			return err
		}
	}
	if value := os.Getenv("WATCHPOST_RETENTION_BATCH"); value != "" {
		batch, err := strconv.Atoi(value)
		if err != nil || batch < 1 || batch > 10000 {
			return fmt.Errorf("WATCHPOST_RETENTION_BATCH: invalid batch")
		}
		r.Batch = batch
	}
	if r.Interval < 0 {
		return fmt.Errorf("WATCHPOST_RETENTION_INTERVAL: cannot be negative")
	}
	return nil
}

// ParseRetentionDuration accepts Go durations ("30m", "24h") and a day suffix
// ("30d", "90d"). An empty or zero value means "keep forever".
func ParseRetentionDuration(value string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" || value == "0" {
		return 0, nil
	}
	if strings.HasSuffix(value, "d") {
		days, err := strconv.Atoi(strings.TrimSuffix(value, "d"))
		if err != nil || days < 0 {
			return 0, fmt.Errorf("invalid day retention %q", value)
		}
		return time.Duration(days) * 24 * time.Hour, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration < 0 {
		return 0, fmt.Errorf("invalid retention %q", value)
	}
	return duration, nil
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