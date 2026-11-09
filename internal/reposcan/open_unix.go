//go:build unix

package reposcan

import (
	"os"
	"syscall"
)

// openNoFollow opens p read-only, refusing a symlink in the last component
// and never blocking on a fifo.
func openNoFollow(p string) (*os.File, error) {
	fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), p), nil
}
