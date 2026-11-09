//go:build !unix

package reposcan

import (
	"errors"
	"os"
)

func openNoFollow(p string) (*os.File, error) {
	st, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	return os.Open(p)
}
