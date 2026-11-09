//go:build linux

package main

import "syscall"

// freeBytes reports bytes available to this process on the data filesystem.
func (s *store) freeBytes() (int64, error) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(s.dir, &st); err != nil {
		return 0, err
	}
	return int64(st.Bavail) * int64(st.Frsize), nil
}
