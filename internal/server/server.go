package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/watchpost-ops/watchpost/internal/actions"
	"github.com/watchpost-ops/watchpost/internal/agent"
	"github.com/watchpost-ops/watchpost/internal/agentpairing"
	"github.com/watchpost-ops/watchpost/internal/auth"
	"github.com/watchpost-ops/watchpost/internal/backup"
	"github.com/watchpost-ops/watchpost/internal/checks"
	"github.com/watchpost-ops/watchpost/internal/collectorhealth"
	"github.com/watchpost-ops/watchpost/internal/config"
	"github.com/watchpost-ops/watchpost/internal/contract"
	"github.com/watchpost-ops/watchpost/internal/devices"
	"github.com/watchpost-ops/watchpost/internal/evidence"
	"github.com/watchpost-ops/watchpost/internal/fleet"
	"github.com/watchpost-ops/watchpost/internal/history"
	"github.com/watchpost-ops/watchpost/internal/incidents"
	"github.com/watchpost-ops/watchpost/internal/ingest"
	"github.com/watchpost-ops/watchpost/internal/notify"
	"github.com/watchpost-ops/watchpost/internal/pairing"
	"github.com/watchpost-ops/watchpost/internal/posts"
	"github.com/watchpost-ops/watchpost/internal/retention"
	"github.com/watchpost-ops/watchpost/internal/rules"
	"github.com/watchpost-ops/watchpost/internal/secrets"
	"github.com/watchpost-ops/watchpost/internal/storage"
	"github.com/watchpost-ops/watchpost/internal/store"
	"github.com/watchpost-ops/watchpost/web"
)

type Server struct {
	cfg          config.Config
	version      string
	logger       *slog.Logger
	store        *store.Store
	auth         *auth.Manager
	posts        *posts.Store
	ingest       *ingest.Service
	history      *history.Store
	rules        *rules.Engine
	notify       *notify.Service
	incidents    *incidents.Store
	evidence     *evidence.Store
	agent        *agent.Service
	agentPairing *agentpairing.Service
	actions      *actions.Registry
	fleet        *fleet.Service
	pairing      *pairing.Service
	health       *collectorhealth.Store
	devices      *devices.ProfileStore
	checks       *checks.ScheduleStore
	retention    *retention.Store
	storage      *storage.Checker
	checkPolicy  *checks.Policy
	checkLimiter *checkRateLimiter
	secrets      *secrets.Box
	backupStatus backupStatus
}

type backupStatus struct {
	mu        sync.Mutex
	lastAt    time.Time
	nextAt    time.Time
	lastError string
	enabled   bool
	dir       string
	retain    int
}

type checkRateLimiter struct {
	mu    sync.Mutex
	times []time.Time
}

// allow applies a sliding one-per-second window on on-demand check execution.
func (l *checkRateLimiter) allow() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	cutoff := time.Now().Add(-time.Minute)
	kept := l.times[:0]
	for _, at := range l.times {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	l.times = kept
	if len(l.times) >= 60 {
		return false
	}
	l.times = append(l.times, time.Now())
	return true
}

func New(cfg config.Config, version string, logger *slog.Logger, database *store.Store) *Server {
	sender := notify.NetworkSender{Client: &http.Client{Timeout: 10 * time.Second}}
	actionRegistry := actions.New(database)
	server := &Server{cfg: cfg, version: version, logger: logger, store: database, auth: auth.New(database), posts: posts.New(database), ingest: ingest.New(database), history: history.New(database), rules: rules.New(database), notify: notify.New(database, sender), incidents: incidents.New(database), evidence: evidence.New(database), agent: agent.New(database, agent.EvidenceProvider{}), agentPairing: agentpairing.New(database), actions: actionRegistry, fleet: fleet.New(database), pairing: pairing.New(database), health: collectorhealth.New(database), devices: devices.NewProfileStore(database), checks: checks.NewScheduleStore(database), retention: retention.New(database, cfg.Retention), storage: storage.New(cfg.DataDir, cfg.Storage.MaxDBBytes, cfg.Storage.MinFreeBytes, cfg.Storage.MinFreePercent)}
	checkPolicy, err := checks.NewPolicy(cfg.CheckPolicy.AllowCIDRs, cfg.CheckPolicy.DenyCIDRs, cfg.CheckPolicy.DenyPorts)
	if err != nil {
		logger.Warn("invalid check policy; all targets allowed", "error", err)
	}
	server.checkPolicy = checkPolicy
	server.checks = checks.NewScheduleStoreWithPolicy(database, checkPolicy)
	server.checkLimiter = &checkRateLimiter{}
	server.secrets = secrets.New(cfg.MasterKey)
	server.devices = devices.NewProfileStoreWithKey(database, server.secrets)
	server.registerActions()
	server.provisionBootstrap()
	return server
}

// registerActions binds the typed action definitions. No action may travel
// through a generic untyped command path, and none grants write capability to
// read-monitoring authority.
func (s *Server) registerActions() {
	_ = s.actions.Register(actions.Definition{Type: "rerun_check", NeedsApproval: false, Validate: func(parameters map[string]any) error {
		if _, ok := parameters["check"].(string); !ok {
			return errors.New("check required")
		}
		return nil
	}, Execute: func(ctx context.Context, postID string, parameters map[string]any) (map[string]any, error) {
		checkID, _ := parameters["check"].(string)
		schedule, err := s.checks.Get(ctx, checkID)
		if err != nil {
			return nil, errors.New("check schedule not found")
		}
		if schedule.PostID != postID {
			return nil, errors.New("check does not belong to this post")
		}
		runner := checks.New(10 * time.Second)
		result := runner.Run(ctx, schedule.Kind, schedule.Address, schedule.ServerName)
		if err := s.ingestCheckResult(ctx, checks.DueResult{Schedule: schedule, Result: result}, time.Now().UTC()); err != nil {
			return nil, err
		}
		// The verification outcome records the observed check evidence.
		latency := float64(result.Latency) / float64(time.Millisecond)
		return map[string]any{"ok": result.OK, "failure": result.Failure, "latency_ms": latency}, nil
	}})
	_ = s.actions.Register(actions.Definition{Type: "silence_route", NeedsApproval: true, Validate: func(parameters map[string]any) error {
		if _, ok := parameters["route_id"].(string); !ok {
			return errors.New("route_id required")
		}
		return nil
	}, Execute: func(ctx context.Context, _ string, parameters map[string]any) (map[string]any, error) {
		result, err := s.store.DB.ExecContext(ctx, `UPDATE notification_routes SET enabled=0 WHERE id=?`, parameters["route_id"])
		if err != nil {
			return nil, err
		}
		count, _ := result.RowsAffected()
		return map[string]any{"disabled": count == 1}, nil
	}})
}

// provisionBootstrap decides whether first-admin setup requires a short-lived
// bootstrap token. Loopback-only listeners may keep setup direct; a
// non-loopback listener or an operator-supplied token requires one. Only the
// token hash is persisted; the raw value is printed to the console once.
func (s *Server) provisionBootstrap() {
	ctx := context.Background()
	required, err := s.auth.SetupRequired(ctx)
	if err != nil {
		s.logger.Warn("cannot determine first-run state", "error", err)
		return
	}
	if !required {
		s.auth.SetBootstrapTokenRequired(false)
		return
	}
	operatorToken := s.cfg.SetupToken != ""
	tokenRequired := operatorToken || !loopbackListener(s.cfg.Listen)
	s.auth.SetBootstrapTokenRequired(tokenRequired)
	if !tokenRequired {
		return
	}
	if operatorToken {
		if err := s.auth.SetBootstrapToken(ctx, s.cfg.SetupToken, time.Now().UTC().Add(s.cfg.SetupTokenTTL)); err != nil {
			s.logger.Warn("bootstrap token could not be stored", "error", err)
		}
		return
	}
	raw, err := s.auth.GenerateBootstrapToken(ctx, s.cfg.SetupTokenTTL)
	if err != nil {
		s.logger.Warn("bootstrap token could not be generated", "error", err)
		return
	}
	fmt.Fprintf(os.Stdout, "Watchpost first-run setup requires a bootstrap token.\nToken: %s (expires %s)\n", raw, time.Now().UTC().Add(s.cfg.SetupTokenTTL).Format(time.RFC3339))
}

func loopbackListener(listen string) bool {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, r *http.Request) {
		if err := s.store.Ready(r.Context()); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not ready"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})
	mux.HandleFunc("GET /api/v1/version", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"version": s.version})
	})
	mux.HandleFunc("GET /api/v1/diagnostics", s.handleDiagnostics)
	mux.HandleFunc("GET /api/v1/storage", s.require("viewer", s.handleStorage))
	mux.HandleFunc("GET /api/v1/backup-status", s.require("viewer", s.handleBackupStatus))
	s.registerAPI(mux)
	assets, err := fs.Sub(web.Files, "dist")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(assets)))
	return securityHeaders(mux)
}

func (s *Server) handleDiagnostics(w http.ResponseWriter, _ *http.Request) {
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	openFDs := -1
	if entries, readErr := os.ReadDir("/proc/self/fd"); readErr == nil {
		openFDs = len(entries)
	}
	storageReport, _ := s.storage.Report()
	writeJSON(w, http.StatusOK, map[string]any{"version": s.version, "schema_version": store.SchemaVersion, "persistence": true, "heap_alloc_bytes": memory.HeapAlloc, "goroutines": runtime.NumGoroutine(), "open_fds": openFDs, "db_size_bytes": storageReport.TotalBytes, "storage_full": storageReport.Full, "storage_reason": storageReport.Reason})
}

func (s *Server) handleStorage(w http.ResponseWriter, r *http.Request) {
	report, err := s.storage.Report()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "storage status unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// guardStorage rejects writes before the node can exhaust disk, and kicks an
// immediate retention pass when the node is over budget so space is reclaimed
// without waiting for the next scheduled pass.
func (s *Server) guardStorage(ctx context.Context) error {
	if err := s.storage.Check(); err != nil {
		go func() {
			passCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			_, _ = s.retention.RunOnce(passCtx)
		}()
		return err
	}
	return nil
}

func (s *Server) Run(ctx context.Context) error {
	httpServer := &http.Server{Addr: s.cfg.Listen, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go s.deliveryLoop(ctx)
	go s.checkLoop(ctx)
	go s.snmpLoop(ctx)
	go s.retentionLoop(ctx)
	go s.backupLoop(ctx)
	errCh := make(chan error, 1)
	go func() {
		s.logger.Info("watchpost listening", "address", s.cfg.Listen, "version", s.version)
		errCh <- httpServer.ListenAndServe()
	}()
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
	}
}

func (s *Server) checkLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	runner := checks.New(10 * time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := s.guardStorage(ctx); err != nil {
				s.logger.Warn("scheduled checks paused; storage full", "error", err)
				continue
			}
			results, err := s.checks.RunDue(ctx, runner, now)
			if err != nil {
				s.logger.Warn("scheduled checks failed", "error", err)
				continue
			}
			for _, due := range results {
				if err := s.ingestCheckResult(ctx, due, now); err != nil {
					s.logger.Warn("check observation ingestion failed", "schedule", due.Schedule.ID, "error", err)
				}
			}
		}
	}
}

// ingestCheckResult routes a stored central-check result through the canonical
// observation contract and the rule engine, so a failed check can fire an
// alert exactly like agent telemetry.
func (s *Server) ingestCheckResult(ctx context.Context, due checks.DueResult, now time.Time) error {
	method := contract.Method{ID: due.Schedule.ID, Kind: contract.MethodCentralCheck, PostID: due.Schedule.PostID}
	observations := due.Result.Observations(method, now.UTC())
	ingested := now.UTC().Format(time.RFC3339Nano)
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var last int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(last_sequence,0) FROM collector_keys WHERE id=?`, due.Schedule.ID).Scan(&last); err != nil {
		return err
	}
	for index, observation := range observations {
		if _, err = tx.ExecContext(ctx, `INSERT INTO observations(post_id,collector_id,observed_at,ingested_at,sequence,signal,value,unit,quality,labels_json) VALUES(?,?,?,?,?,?,?,?,?,?)`, observation.PostID, due.Schedule.ID, observation.ObservedAt.UTC().Format(time.RFC3339Nano), ingested, last+int64(index)+1, observation.Signal, observation.Value, observation.Unit, string(observation.Quality), "{}"); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE collector_keys SET last_sequence=?,last_seen_at=?,last_observed_at=? WHERE id=?`, last+int64(len(observations)), ingested, ingested, due.Schedule.ID); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	for _, observation := range observations {
		alerts, err := s.rules.EvaluateObservation(ctx, observation.PostID, observation.Signal, observation.ObservedAt, observation.Value, string(observation.Quality))
		if err != nil {
			return err
		}
		for _, alert := range alerts {
			if alert.State == "firing" {
				_ = s.notify.Queue(ctx, alert.ID)
			}
		}
	}
	return nil
}

func (s *Server) deliveryLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.notify.DeliverDue(ctx, 25); err != nil {
				s.logger.Error("notification delivery", "error", err)
			}
		}
	}
}

func (s *Server) retentionLoop(ctx context.Context) {
	if report, err := s.retention.RunOnce(ctx); err != nil {
		s.logger.Warn("initial retention pass failed", "error", err)
	} else if report.Total() > 0 {
		s.logger.Info("retention pass completed", "categories", report.Categories)
	}
	s.retention.RunLoop(ctx)
}

// backupLoop runs scheduled online backups. It is enabled only when a backup
// directory and a positive schedule are configured.
func (s *Server) backupLoop(ctx context.Context) {
	if s.cfg.Backup.Dir == "" || s.cfg.Backup.Schedule <= 0 {
		return
	}
	s.backupStatus.mu.Lock()
	s.backupStatus.enabled = true
	s.backupStatus.dir = s.cfg.Backup.Dir
	s.backupStatus.retain = s.cfg.Backup.Retain
	s.backupStatus.nextAt = time.Now().UTC()
	s.backupStatus.mu.Unlock()
	s.runScheduledBackup(ctx)
	ticker := time.NewTicker(s.cfg.Backup.Schedule)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.runScheduledBackup(ctx)
		}
	}
}

func (s *Server) runScheduledBackup(ctx context.Context) {
	now := time.Now().UTC()
	passphrase := ""
	if s.cfg.Backup.PassphraseFile != "" {
		content, err := os.ReadFile(s.cfg.Backup.PassphraseFile)
		if err != nil {
			s.setBackupError(now, "read passphrase file: "+err.Error())
			return
		}
		passphrase = strings.TrimRight(string(content), "\r\n")
	}
	output := filepath.Join(s.cfg.Backup.Dir, "watchpost-"+now.Format("20060102T150405Z")+".wpbk")
	if err := backup.Create(ctx, s.store, output, passphrase); err != nil {
		s.setBackupError(now, err.Error())
		return
	}
	if s.cfg.Backup.Retain > 0 {
		if err := s.pruneBackups(now); err != nil {
			s.logger.Warn("backup pruning failed", "error", err)
		}
	}
	s.backupStatus.mu.Lock()
	s.backupStatus.lastAt = now
	s.backupStatus.nextAt = now.Add(s.cfg.Backup.Schedule)
	s.backupStatus.lastError = ""
	s.backupStatus.mu.Unlock()
	s.logger.Info("scheduled backup completed", "output", output)
}

func (s *Server) pruneBackups(now time.Time) error {
	entries, err := os.ReadDir(s.cfg.Backup.Dir)
	if err != nil {
		return err
	}
	names := []string{}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".wpbk") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for len(names) > s.cfg.Backup.Retain {
		remove := names[0]
		names = names[1:]
		if err := os.Remove(filepath.Join(s.cfg.Backup.Dir, remove)); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) setBackupError(at time.Time, message string) {
	s.backupStatus.mu.Lock()
	s.backupStatus.lastError = message
	s.backupStatus.lastAt = at
	s.backupStatus.mu.Unlock()
	s.logger.Warn("scheduled backup failed", "error", message)
}

func (s *Server) handleBackupStatus(w http.ResponseWriter, _ *http.Request) {
	s.backupStatus.mu.Lock()
	defer s.backupStatus.mu.Unlock()
	writeJSON(w, 200, map[string]any{
		"enabled": s.backupStatus.enabled, "dir": s.backupStatus.dir, "retain": s.backupStatus.retain,
		"last_backup_at": nullableTime(s.backupStatus.lastAt), "next_backup_at": nullableTime(s.backupStatus.nextAt), "last_error": s.backupStatus.lastError,
	})
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.Format(time.RFC3339)
}

// snmpLoop executes recurring read-only device polls and routes the results
// through the canonical observation and rule pipeline.
func (s *Server) snmpLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			if err := s.guardStorage(ctx); err != nil {
				continue
			}
			if err := s.runDueSNMP(ctx, now); err != nil {
				s.logger.Warn("scheduled SNMP failed", "error", err)
			}
		}
	}
}

func (s *Server) runDueSNMP(ctx context.Context, now time.Time) error {
	profiles, err := s.devices.Due(ctx, now, 16)
	if err != nil {
		return err
	}
	for _, profile := range profiles {
		if err := s.pollDeviceProfile(ctx, profile, now); err != nil {
			s.logger.Warn("scheduled SNMP poll failed", "profile", profile.ID, "error", err)
		}
	}
	return nil
}

// pollDeviceProfile performs one read-only poll, stores its observations, runs
// rule evaluation and reschedules the profile. A failed poll emits an explicit
// snmp.poll_ok=0 observation so a deterministic rule can fire on reachability.
func (s *Server) pollDeviceProfile(ctx context.Context, profile devices.SavedProfile, now time.Time) error {
	_, config, err := s.devices.Credentials(ctx, profile.ID)
	if err != nil {
		s.devices.Advance(ctx, profile.ID, profile.IntervalSeconds, now)
		return err
	}
	client, err := devices.NewV3(config)
	if err != nil {
		s.devices.Advance(ctx, profile.ID, profile.IntervalSeconds, now)
		return err
	}
	if err := client.Connect(); err != nil {
		client.Conn.Close()
		s.devices.Advance(ctx, profile.ID, profile.IntervalSeconds, now)
		return s.emitDevicePoll(ctx, profile, false, nil, now)
	}
	defer client.Conn.Close()
	readings, err := devices.Poll(ctx, client, devices.Profile{ID: profile.ID, Kind: profile.Kind, OIDs: profile.OIDs})
	if err != nil {
		s.devices.Advance(ctx, profile.ID, profile.IntervalSeconds, now)
		return s.emitDevicePoll(ctx, profile, false, nil, now)
	}
	if err := s.emitDevicePoll(ctx, profile, true, readings, now); err != nil {
		return err
	}
	return s.devices.Advance(ctx, profile.ID, profile.IntervalSeconds, now)
}

func (s *Server) emitDevicePoll(ctx context.Context, profile devices.SavedProfile, ok bool, readings []devices.Reading, now time.Time) error {
	method := contract.Method{ID: profile.ID, Kind: contract.MethodDeviceSNMP, PostID: profile.PostID}
	observations := []contract.Observation{devices.PollOK(method, ok, now.UTC())}
	for _, reading := range readings {
		observations = append(observations, reading.Observation(method, now.UTC()))
	}
	return s.ingestContractObservations(ctx, profile.ID, profile.PostID, observations, now)
}

// ingestContractObservations assigns contiguous sequences and inserts
// observations for a monitoring-method source, then evaluates rules exactly
// like agent telemetry.
func (s *Server) ingestContractObservations(ctx context.Context, sourceID, postID string, observations []contract.Observation, now time.Time) error {
	ingested := now.UTC().Format(time.RFC3339Nano)
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var last int64
	if err = tx.QueryRowContext(ctx, `SELECT COALESCE(last_sequence,0) FROM collector_keys WHERE id=?`, sourceID).Scan(&last); err != nil {
		return err
	}
	for index, observation := range observations {
		if _, err = tx.ExecContext(ctx, `INSERT INTO observations(post_id,collector_id,observed_at,ingested_at,sequence,signal,value,unit,quality,labels_json) VALUES(?,?,?,?,?,?,?,?,?,?)`, observation.PostID, sourceID, observation.ObservedAt.UTC().Format(time.RFC3339Nano), ingested, last+int64(index)+1, observation.Signal, observation.Value, observation.Unit, string(observation.Quality), "{}"); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `UPDATE collector_keys SET last_sequence=?,last_seen_at=?,last_observed_at=?,last_error='' WHERE id=?`, last+int64(len(observations)), ingested, ingested, sourceID); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	for _, observation := range observations {
		alerts, err := s.rules.EvaluateObservation(ctx, observation.PostID, observation.Signal, observation.ObservedAt, observation.Value, string(observation.Quality))
		if err != nil {
			return err
		}
		for _, alert := range alerts {
			if alert.State == "firing" {
				_ = s.notify.Queue(ctx, alert.ID)
			}
		}
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
