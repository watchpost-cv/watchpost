package collectorclient

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Config struct {
	Version     int    `json:"version"`
	ServerURL   string `json:"server_url"`
	PostID      string `json:"post_id"`
	CollectorID string `json:"collector_id"`
	Secret      string `json:"secret"`
}

func Pair(serverURL, token, collectorID, configPath string, client *http.Client) (Config, error) {
	base, err := url.Parse(strings.TrimRight(serverURL, "/"))
	if err != nil || base.Host == "" {
		return Config{}, errors.New("invalid Watchpost server URL")
	}
	host, _, _ := net.SplitHostPort(base.Host)
	if host == "" {
		host = base.Hostname()
	}
	if base.Scheme != "https" && !(base.Scheme == "http" && (host == "127.0.0.1" || host == "localhost" || host == "::1")) {
		return Config{}, errors.New("pairing requires HTTPS except on loopback")
	}
	payload, _ := json.Marshal(map[string]string{"token": token, "collector_id": collectorID})
	request, _ := http.NewRequest(http.MethodPost, base.String()+"/api/collector/v1/pair", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	response, err := client.Do(request)
	if err != nil {
		return Config{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		return Config{}, fmt.Errorf("pairing rejected (%d)", response.StatusCode)
	}
	var result struct {
		Version     int    `json:"version"`
		PostID      string `json:"post_id"`
		CollectorID string `json:"collector_id"`
		Secret      string `json:"secret"`
	}
	if json.NewDecoder(response.Body).Decode(&result) != nil || result.Version != 1 || result.Secret == "" {
		return Config{}, errors.New("invalid pairing response")
	}
	config := Config{Version: 1, ServerURL: base.String(), PostID: result.PostID, CollectorID: result.CollectorID, Secret: result.Secret}
	if err = Save(configPath, config); err != nil {
		return Config{}, err
	}
	return config, nil
}

func Save(path string, config Config) error {
	if path == "" {
		return errors.New("collector config path required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	var config Config
	if json.Unmarshal(data, &config) != nil || config.Version != 1 || config.Secret == "" {
		return Config{}, errors.New("invalid collector config")
	}
	return config, nil
}
