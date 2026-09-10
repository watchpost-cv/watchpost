package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	corelauncher "github.com/gantry-tools/gantry-core/launcher"
)

func (s *Server) launcherRoot(static http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.URL.Query().Has("config") {
			s.serveLauncher(static, w, r)
			return
		}
		instances, err := s.loadLauncherInstances(r.Context())
		if err != nil {
			http.Error(w, "launcher unavailable", http.StatusInternalServerError)
			return
		}
		switch len(instances) {
		case 0:
			http.Redirect(w, r, "/app/", http.StatusFound)
		case 1:
			target, err := corelauncher.AppURL(instances[0])
			if err != nil {
				http.Error(w, "invalid launcher configuration", http.StatusInternalServerError)
				return
			}
			http.Redirect(w, r, target, http.StatusFound)
		default:
			s.serveLauncher(static, w, r)
		}
	}
}

func (s *Server) serveLauncher(static http.Handler, w http.ResponseWriter, r *http.Request) {
	clone := r.Clone(r.Context())
	clone.URL.Path, clone.URL.RawPath = "/launcher.html", ""
	w.Header().Set("Cache-Control", "no-store")
	static.ServeHTTP(w, clone)
}

func (s *Server) launcherSession(r *http.Request, mutation bool) (string, bool) {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return "", false
	}
	session, err := s.auth.Authenticate(r.Context(), cookie.Value)
	if err != nil || session.User.Role != "admin" {
		return "", false
	}
	if mutation && r.Header.Get("X-Watchpost-CSRF") != session.CSRF {
		return "", false
	}
	return session.CSRF, true
}

func (s *Server) handleLauncherInstances(w http.ResponseWriter, r *http.Request) {
	instances, err := s.loadLauncherInstances(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "launcher unavailable"})
		return
	}
	view, err := corelauncher.MakeView("watchpost", instances)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "invalid launcher configuration"})
		return
	}
	writeJSON(w, 200, view)
}

func (s *Server) handleLauncherConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.launcherSession(r, true); !ok {
		writeJSON(w, 403, map[string]string{"error": "launcher.configure.all capability and CSRF token required"})
		return
	}
	var document corelauncher.Document
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		writeJSON(w, 400, map[string]string{"error": "invalid json"})
		return
	}
	instances, err := corelauncher.Normalize("watchpost", document)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	if err := s.replaceLauncherInstances(r.Context(), instances); err != nil {
		writeJSON(w, 500, map[string]string{"error": "unable to save launcher configuration"})
		return
	}
	view, _ := corelauncher.MakeView("watchpost", instances)
	writeJSON(w, 200, view)
}

func (s *Server) loadLauncherInstances(ctx context.Context) ([]corelauncher.Instance, error) {
	rows, err := s.store.DB.QueryContext(ctx, "SELECT id,name,domain,port FROM launcher_instances ORDER BY position,id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []corelauncher.Instance{}
	for rows.Next() {
		var item corelauncher.Instance
		if err := rows.Scan(&item.ID, &item.Name, &item.Domain, &item.Port); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Server) replaceLauncherInstances(ctx context.Context, instances []corelauncher.Instance) error {
	tx, err := s.store.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "DELETE FROM launcher_instances"); err != nil {
		return err
	}
	for position, item := range instances {
		if _, err := tx.ExecContext(ctx, "INSERT INTO launcher_instances(id,position,name,domain,port) VALUES(?,?,?,?,?)", item.ID, position, item.Name, item.Domain, item.Port); err != nil {
			return fmt.Errorf("save launcher instance: %w", err)
		}
	}
	return tx.Commit()
}
