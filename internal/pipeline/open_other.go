//go:build !unix

package pipeline

import "os"

func openAppend(path string) (*os.File, error) {
	st, err := os.Lstat(path)
	if err == nil && st.Mode()&os.ModeSymlink != 0 {
		return nil, os.ErrInvalid
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
}

func writeNoFollow(path string, b []byte) error {
	st, err := os.Lstat(path)
	if err == nil && st.Mode()&os.ModeSymlink != 0 {
		return os.ErrInvalid
	}
	return os.WriteFile(path, b, 0o600)
}
