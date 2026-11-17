//go:build unix

package pipeline

import (
	"os"
	"syscall"
)

func openAppend(path string) (*os.File, error) {
	flag := syscall.O_WRONLY | syscall.O_APPEND | syscall.O_CREAT | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	fd, err := syscall.Open(path, flag, 0o600)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func writeNoFollow(path string, b []byte) error {
	flag := syscall.O_WRONLY | syscall.O_TRUNC | syscall.O_CREAT | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	fd, err := syscall.Open(path, flag, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	_, err = f.Write(b)
	return err
}
