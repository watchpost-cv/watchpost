package server

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net/http"
	"time"

	"github.com/watchpost-ops/watchpost/internal/actions"
	"github.com/watchpost-ops/watchpost/internal/agent"
	"github.com/watchpost-ops/watchpost/internal/auth"
	"github.com/watchpost-ops/watchpost/internal/config"
	"github.com/watchpost-ops/watchpost/internal/evidence"
	"github.com/watchpost-ops/watchpost/internal/fleet"
	"github.com/watchpost-ops/watchpost/internal/history"
	"github.com/watchpost-ops/watchpost/internal/incidents"
	"github.com/watchpost-ops/watchpost/internal/ingest"
	"github.com/watchpost-ops/watchpost/internal/notify"
	"github.com/watchpost-ops/watchpost/internal/pairing"
	"github.com/watchpost-ops/watchpost/internal/posts"
	"github.com/watchpost-ops/watchpost/internal/rules"
	"github.com/watchpost-ops/watchpost/internal/store"
	"github.com/watchpost-ops/watchpost/web"
)

type Server struct {
	cfg       config.Config
	version   string
	logger    *slog.Logger
	store     *store.Store
	auth      *auth.Manager
	posts     *posts.Store
	ingest    *ingest.Service
	history   *history.Store
	rules     *rules.Engine
	notify    *notify.Service
	incidents *incidents.Store
	evidence  *evidence.Store
	agent     *agent.Service
	actions   *actions.Registry
	fleet     *fleet.Service
	pairing   *pairing.Service
}

func New(cfg config.Config, version string, logger *slog.Logger, database *store.Store) *Server {
	sender := notify.NetworkSender{Client: &http.Client{Timeout: 10 * time.Second}}
	actionRegistry := actions.New(database)
	_ = actionRegistry.Register(actions.Definition{Type: "rerun_check", NeedsApproval: false, Validate: func(parameters map[string]any) error {
		if _, ok := parameters["check"].(string); !ok {
			return errors.New("check required")
		}
		return nil
	}, Execute: func(context.Context, string, map[string]any) (map[string]any, error) {
		return map[string]any{"scheduled": true}, nil
	}})
	_ = actionRegistry.Register(actions.Definition{Type: "silence_route", NeedsApproval: true, Validate: func(parameters map[string]any) error {
		if _, ok := parameters["route_id"].(string); !ok {
			return errors.New("route_id required")
		}
		return nil
	}, Execute: func(ctx context.Context, _ string, parameters map[string]any) (map[string]any, error) {
		result, err := database.DB.ExecContext(ctx, `UPDATE notification_routes SET enabled=0 WHERE id=?`, parameters["route_id"])
		if err != nil {
			return nil, err
		}
		count, _ := result.RowsAffected()
		return map[string]any{"disabled": count == 1}, nil
	}})
	return &Server{cfg: cfg, version: version, logger: logger, store: database, auth: auth.New(database), posts: posts.New(database), ingest: ingest.New(database), history: history.New(database), rules: rules.New(database), notify: notify.New(database, sender), incidents: incidents.New(database), evidence: evidence.New(database), agent: agent.New(database, agent.EvidenceProvider{}), actions: actionRegistry, fleet: fleet.New(database), pairing: pairing.New(database)}
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
	mux.HandleFunc("GET /api/v1/diagnostics", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"version": s.version, "schema_version": store.SchemaVersion, "persistence": true})
	})
	s.registerAPI(mux)
	assets, err := fs.Sub(web.Files, "dist")
	if err != nil {
		panic(err)
	}
	mux.Handle("/", http.FileServer(http.FS(assets)))
	return securityHeaders(mux)
}

func (s *Server) Run(ctx context.Context) error {
	httpServer := &http.Server{Addr: s.cfg.Listen, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go s.deliveryLoop(ctx)
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
