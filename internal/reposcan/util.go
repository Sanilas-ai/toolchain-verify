package reposcan

import (
	"bytes"
	"io"
	"sort"
)

func bytesReader(b []byte) io.Reader { return bytes.NewReader(b) }
func sortStrings(s []string)         { sort.Strings(s) }
