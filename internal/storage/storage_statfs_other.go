//go:build !linux && !darwin

package storage

import "errors"

// statfs is unavailable on unsupported platforms; the free-disk guard is
// skipped and capacity protection falls back to the database-footprint cap.
func statfs(path string) (statfsResult, error) {
	return statfsResult{}, errors.New("filesystem statistics unavailable")
}

type statfsResult struct {
	Bavail, Blocks uint64
	Bsize          int64
}