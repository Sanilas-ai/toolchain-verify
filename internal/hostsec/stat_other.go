//go:build !unix

package hostsec

import "os"

func fileUID(os.FileInfo) (int, bool) { return 0, false }
