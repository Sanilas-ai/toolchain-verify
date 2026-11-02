//go:build !unix

package agent

import "os"

func fileUID(os.FileInfo) (int, bool) { return 0, false }
