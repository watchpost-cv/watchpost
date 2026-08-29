package storage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFootprintCountsAllSidecars(t *testing.T) {
	dir := t.TempDir()
	write := func(name string, size int) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), make([]byte, size), 0600); err != nil {
			t.Fatal(err)
		}
	}
	write("watchpost.db", 100)
	write("watchpost.db-wal", 50)
	write("watchpost.db-shm", 10)
	write("unrelated.txt", 999)
	checker := New(dir, 0, 0, 0)
	report, err := checker.Report()
	if err != nil {
		t.Fatal(err)
	}
	if report.DBBytes != 100 || report.WALBytes != 50 || report.SHMBytes != 10 || report.TotalBytes != 160 {
		t.Fatalf("unexpected footprint: %#v", report)
	}
}

func TestCheckFailsClosedAtCapacity(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "watchpost.db"), make([]byte, 4096), 0600); err != nil {
		t.Fatal(err)
	}
	checker := New(dir, 1024, 0, 0)
	if err := checker.Check(); err != ErrStorageFull {
		t.Fatalf("Check() = %v want ErrStorageFull", err)
	}
}

func TestCheckAllowsUnderCapacity(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "watchpost.db"), make([]byte, 1024), 0600); err != nil {
		t.Fatal(err)
	}
	checker := New(dir, 4096, 0, 0)
	if err := checker.Check(); err != nil {
		t.Fatalf("Check() = %v want nil", err)
	}
}

func TestReportReportsFreeSpace(t *testing.T) {
	checker := New(t.TempDir(), 0, 0, 0)
	report, err := checker.Report()
	if err != nil {
		t.Fatal(err)
	}
	if report.FreeBytes <= 0 {
		t.Fatalf("expected positive free space, got %d", report.FreeBytes)
	}
	if report.FreePercent <= 0 || report.FreePercent > 100 {
		t.Fatalf("unexpected free percent %f", report.FreePercent)
	}
}
