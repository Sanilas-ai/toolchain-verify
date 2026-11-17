//go:build windows

package reposcan

import (
	"os"
	"syscall"
)

const fileFlagOpenReparsePoint = 0x00200000

// openNoFollow opens p read-only. A reparse point (symlink, mount, junction)
// is refused so the scan cannot be steered onto another file.
func openNoFollow(p string) (*os.File, error) {
	p16, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		return nil, err
	}
	h, err := syscall.CreateFile(
		p16,
		syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE,
		nil,
		syscall.OPEN_EXISTING,
		syscall.FILE_ATTRIBUTE_NORMAL|fileFlagOpenReparsePoint,
		0,
	)
	if err != nil {
		return nil, err
	}
	var info syscall.ByHandleFileInformation
	if err := syscall.GetFileInformationByHandle(h, &info); err != nil {
		syscall.CloseHandle(h)
		return nil, err
	}
	if info.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		syscall.CloseHandle(h)
		return nil, ErrReparse
	}
	return os.NewFile(uintptr(h), p), nil
}
