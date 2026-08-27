package host

import (
	"bufio"
	"errors"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Snapshot struct {
	ObservedAt      time.Time `json:"observed_at"`
	CPUUser         uint64    `json:"cpu_user_ticks"`
	CPUSystem       uint64    `json:"cpu_system_ticks"`
	CPUIdle         uint64    `json:"cpu_idle_ticks"`
	MemoryTotal     uint64    `json:"memory_total_bytes"`
	MemoryAvailable uint64    `json:"memory_available_bytes"`
	UptimeSeconds   float64   `json:"uptime_seconds"`
	Load1           float64   `json:"load_1"`
	Load5           float64   `json:"load_5"`
	Load15          float64   `json:"load_15"`
	RootTotal       uint64    `json:"root_total_bytes"`
	RootFree        uint64    `json:"root_free_bytes"`
}

func Collect() (Snapshot, error) {
	var s Snapshot
	s.ObservedAt = time.Now().UTC()
	stat, err := os.ReadFile("/proc/stat")
	if err != nil {
		return s, err
	}
	fields := strings.Fields(strings.SplitN(string(stat), "\n", 2)[0])
	if len(fields) < 5 {
		return s, errors.New("malformed /proc/stat")
	}
	s.CPUUser, _ = strconv.ParseUint(fields[1], 10, 64)
	s.CPUSystem, _ = strconv.ParseUint(fields[3], 10, 64)
	s.CPUIdle, _ = strconv.ParseUint(fields[4], 10, 64)
	mem, err := os.Open("/proc/meminfo")
	if err != nil {
		return s, err
	}
	scanner := bufio.NewScanner(mem)
	for scanner.Scan() {
		f := strings.Fields(scanner.Text())
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		switch strings.TrimSuffix(f[0], ":") {
		case "MemTotal":
			s.MemoryTotal = v * 1024
		case "MemAvailable":
			s.MemoryAvailable = v * 1024
		}
	}
	mem.Close()
	up, _ := os.ReadFile("/proc/uptime")
	if f := strings.Fields(string(up)); len(f) > 0 {
		s.UptimeSeconds, _ = strconv.ParseFloat(f[0], 64)
	}
	load, _ := os.ReadFile("/proc/loadavg")
	if f := strings.Fields(string(load)); len(f) >= 3 {
		s.Load1, _ = strconv.ParseFloat(f[0], 64)
		s.Load5, _ = strconv.ParseFloat(f[1], 64)
		s.Load15, _ = strconv.ParseFloat(f[2], 64)
	}
	var fs syscall.Statfs_t
	if err = syscall.Statfs("/", &fs); err == nil {
		s.RootTotal = fs.Blocks * uint64(fs.Bsize)
		s.RootFree = fs.Bavail * uint64(fs.Bsize)
	}
	return s, scanner.Err()
}
