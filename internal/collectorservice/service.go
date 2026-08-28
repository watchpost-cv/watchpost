package collectorservice

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

type Paths struct {
	Binary, Config, Unit string
	System               bool
}
type Runner func(string, ...string) error
type Manager struct{ Run Runner }

func New() Manager {
	return Manager{Run: func(name string, args ...string) error {
		command := exec.Command(name, args...)
		command.Stdout = os.Stdout
		command.Stderr = os.Stderr
		command.Stdin = os.Stdin
		return command.Run()
	}}
}

func Resolve(system bool, config string) (Paths, error) {
	if system {
		if os.Geteuid() != 0 {
			return Paths{}, errors.New("--system requires root")
		}
		if config == "" {
			config = "/etc/watchpost/collector.json"
		}
		return Paths{Binary: "/usr/local/lib/watchpost/watchpost", Config: config, Unit: "/etc/systemd/system/watchpost-collector.service", System: true}, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, err
	}
	if config == "" {
		config = filepath.Join(home, ".config", "watchpost", "collector.json")
	}
	return Paths{Binary: filepath.Join(home, ".local", "lib", "watchpost", "watchpost"), Config: config, Unit: filepath.Join(home, ".config", "systemd", "user", "watchpost-collector.service")}, nil
}

func Unit(paths Paths) string {
	wanted := "default.target"
	if paths.System {
		wanted = "multi-user.target"
	}
	return fmt.Sprintf(`[Unit]
Description=Watchpost host collector
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=%s collector run --config %s
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%s

[Install]
WantedBy=%s
`, paths.Binary, paths.Config, filepath.Dir(paths.Config), wanted)
}

func (m Manager) Install(source string, paths Paths) error {
	if _, err := os.Stat(paths.Config); err != nil {
		return fmt.Errorf("pair the collector first: %w", err)
	}
	if err := copyFile(source, paths.Binary, 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(paths.Unit), 0755); err != nil {
		return err
	}
	if err := os.WriteFile(paths.Unit, []byte(Unit(paths)), 0644); err != nil {
		return err
	}
	if err := m.systemctl(paths, "daemon-reload"); err != nil {
		return err
	}
	return m.systemctl(paths, "enable", "--now", "watchpost-collector.service")
}
func (m Manager) Status(paths Paths) error {
	return m.systemctl(paths, "status", "--no-pager", "watchpost-collector.service")
}
func (m Manager) Logs(paths Paths) error {
	args := []string{"--no-pager", "-n", "100"}
	if paths.System {
		args = append(args, "-u")
	} else {
		args = append(args, "--user-unit")
	}
	args = append(args, "watchpost-collector.service")
	return m.Run("journalctl", args...)
}
func (m Manager) Uninstall(paths Paths) error {
	_ = m.systemctl(paths, "disable", "--now", "watchpost-collector.service")
	if err := os.Remove(paths.Unit); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = m.systemctl(paths, "daemon-reload")
	return nil
}
func (m Manager) systemctl(paths Paths, args ...string) error {
	if !paths.System {
		args = append([]string{"--user"}, args...)
	}
	return m.Run("systemctl", args...)
}

func copyFile(source, destination string, mode os.FileMode) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err = os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
		return err
	}
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	if _, err = io.Copy(output, input); err != nil {
		output.Close()
		return err
	}
	if err = output.Close(); err != nil {
		return err
	}
	return os.Chmod(destination, mode)
}
