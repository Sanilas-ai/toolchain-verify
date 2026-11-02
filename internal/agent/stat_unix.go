//go:build unix

package agent

import (
	"os"
	"syscall"
)

func fileUID(st os.FileInfo) (int, bool) {
	if s, ok := st.Sys().(*syscall.Stat_t); ok {
		return int(s.Uid), true
	}
	return 0, false
}
