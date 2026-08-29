//go:build linux || darwin

package storage

import "syscall"

func statfs(path string) (syscall.Statfs_t, error) {
	var stat syscall.Statfs_t
	err := syscall.Statfs(path, &stat)
	return stat, err
}