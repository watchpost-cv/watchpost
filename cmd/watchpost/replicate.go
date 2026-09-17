package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

// runReplicate drives the explicit raft membership / runtime-status operator
// surface against the local (or --url) Watchpost node. Raft membership is an
// explicit consensus configuration operation: a Gantry cluster_members peer is
// never automatically promoted to a raft voter.
func runReplicate(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: watchpost replicate <status|join>")
	}
	command := args[0]
	fs := flag.NewFlagSet("watchpost replicate "+command, flag.ContinueOnError)
	url := fs.String("url", "", "Watchpost base URL (default from WATCHPOST_URL or http://127.0.0.1:7334)")
	user := fs.String("user", "admin", "admin username")
	pass := fs.String("pass", "", "admin password (default WATCHPOST_ADMIN_PASSWORD)")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	if *pass == "" {
		*pass = os.Getenv("WATCHPOST_ADMIN_PASSWORD")
	}
	if *url == "" {
		*url = os.Getenv("WATCHPOST_URL")
	}
	if *url == "" {
		*url = "http://127.0.0.1:7334"
	}
	*url = strings.TrimRight(*url, "/")

	client := &http.Client{}
	session, err := replicateLogin(client, *url, *user, *pass)
	if err != nil {
		return err
	}

	switch command {
	case "snapshot":
		body, err := replicateCall(client, *url, http.MethodPost, "/api/v1/replication/snapshot", nil, session)
		if err != nil {
			return err
		}
		fmt.Println(string(body))
		return nil
	case "status":
		body, err := replicateCall(client, *url, http.MethodGet, "/api/v1/replication/status", nil, session)
		if err != nil {
			return err
		}
		var out map[string]any
		_ = json.Unmarshal(body, &out)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	case "join":
		if fs.NArg() != 2 {
			return errors.New("usage: watchpost replicate join <node-id> <address>")
		}
		payload := map[string]string{"node_id": fs.Arg(0), "address": fs.Arg(1)}
		body, err := replicateCall(client, *url, http.MethodPost, "/api/v1/replication/join", payload, session)
		if err != nil {
			return err
		}
		fmt.Println(string(body))
		return nil
	default:
		return fmt.Errorf("unknown replicate command %q", command)
	}
}

type replicateAuth struct {
	cookie *http.Cookie
	csrf   string
}

func replicateLogin(client *http.Client, base, user, pass string) (*replicateAuth, error) {
	do := func(method, path string, payload any, cookie *http.Cookie, csrf string) (*http.Response, []byte, error) {
		var rd io.Reader
		if payload != nil {
			b, _ := json.Marshal(payload)
			rd = bytes.NewReader(b)
		}
		req, err := http.NewRequest(method, base+path, rd)
		if err != nil {
			return nil, nil, err
		}
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if csrf != "" {
			req.Header.Set("X-Watchpost-CSRF", csrf)
		}
		resp, err := client.Do(req)
		if err != nil {
			return nil, nil, err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, b, nil
	}
	_, _, _ = do(http.MethodPost, "/api/v1/setup", map[string]string{"username": user, "email": user + "@example.com", "password": pass}, nil, "")
	login, body, err := do(http.MethodPost, "/api/v1/login", map[string]string{"email": user + "@example.com", "password": pass}, nil, "")
	if err != nil {
		return nil, err
	}
	if login.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("login failed (%d): %s", login.StatusCode, body)
	}
	var session struct {
		CSRF string `json:"csrf_token"`
	}
	_ = json.Unmarshal(body, &session)
	cookies := login.Cookies()
	if len(cookies) == 0 {
		return nil, errors.New("no session cookie returned")
	}
	return &replicateAuth{cookie: cookies[0], csrf: session.CSRF}, nil
}

func replicateCall(client *http.Client, base, method, path string, payload any, s *replicateAuth) ([]byte, error) {
	var rd io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, base+path, rd)
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.AddCookie(s.cookie)
	req.Header.Set("X-Watchpost-CSRF", s.csrf)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("%s %s failed (%d): %s", method, path, resp.StatusCode, body)
	}
	return body, nil
}
