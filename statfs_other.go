//go:build !linux

package main

import "errors"

// freeBytes is only implemented on Linux; elsewhere the disk floor check is
// skipped (freeBytes error -> check bypassed).
func (s *store) freeBytes() (int64, error) {
	return 0, errors.New("statfs unsupported on this platform")
}
