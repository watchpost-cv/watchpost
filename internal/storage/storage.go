package storage

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Report describes the total SQLite footprint (main database plus write-ahead
// and shared-memory sidecars) and the free space on the filesystem hosting the
// data directory.
type Report struct {
	DBBytes        int64   `json:"db_bytes"`
	WALBytes       int64   `json:"wal_bytes"`
	SHMBytes       int64   `json:"shm_bytes"`
	OtherBytes     int64   `json:"other_bytes"`
	TotalBytes     int64   `json:"total_bytes"`
	CapBytes       int64   `json:"cap_bytes"`
	FreeBytes      int64   `json:"free_bytes"`
	FreePercent    float64 `json:"free_percent"`
	MinFreeBytes   int64   `json:"min_free_bytes"`
	MinFreePercent float64 `json:"min_free_percent"`
	Full           bool    `json:"full"`
	Reason         string  `json:"reason,omitempty"`
	Files          []File  `json:"files"`
}

type File struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
}

type Checker struct {
	dataDir        string
	maxDBBytes     int64
	minFreeBytes   int64
	minFreePercent float64
}

func New(dataDir string, maxDBBytes, minFreeBytes int64, minFreePercent float64) *Checker {
	return &Checker{dataDir: dataDir, maxDBBytes: maxDBBytes, minFreeBytes: minFreeBytes, minFreePercent: minFreePercent}
}

var ErrStorageFull = errors.New("storage full")

func (c *Checker) Report() (Report, error) {
	report := Report{CapBytes: c.maxDBBytes, MinFreeBytes: c.minFreeBytes, MinFreePercent: c.minFreePercent}
	entries, err := os.ReadDir(c.dataDir)
	if err != nil {
		return report, err
	}
	names := []string{}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasPrefix(entry.Name(), "watchpost.db") {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)
	for _, name := range names {
		info, err := os.Stat(filepath.Join(c.dataDir, name))
		if err != nil {
			continue
		}
		file := File{Name: name, Size: info.Size()}
		report.Files = append(report.Files, file)
		report.TotalBytes += info.Size()
		switch {
		case strings.HasSuffix(name, "-wal"):
			report.WALBytes += info.Size()
		case strings.HasSuffix(name, "-shm"):
			report.SHMBytes += info.Size()
		case name == "watchpost.db":
			report.DBBytes += info.Size()
		default:
			report.OtherBytes += info.Size()
		}
	}
	if stat, err := statfs(c.dataDir); err == nil {
		report.FreeBytes = int64(stat.Bavail) * int64(stat.Bsize)
		total := int64(stat.Blocks) * int64(stat.Bsize)
		if total > 0 {
			report.FreePercent = 100 * float64(report.FreeBytes) / float64(total)
		}
	}
	switch {
	case c.maxDBBytes > 0 && report.TotalBytes >= c.maxDBBytes:
		report.Full = true
		report.Reason = "database footprint at capacity"
	case c.minFreeBytes > 0 && report.FreeBytes > 0 && report.FreeBytes < c.minFreeBytes:
		report.Full = true
		report.Reason = "free disk below minimum"
	case c.minFreePercent > 0 && report.FreePercent > 0 && report.FreePercent < c.minFreePercent:
		report.Full = true
		report.Reason = "free disk below minimum percent"
	}
	return report, nil
}

func (c *Checker) Check() error {
	report, err := c.Report()
	if err != nil {
		return err
	}
	if report.Full {
		return ErrStorageFull
	}
	return nil
}
