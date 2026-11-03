package models

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// GGUF structural checks: header, metadata and tensor table bounds (the
// classes of input behind llama.cpp/ggml GGUF parsing CVEs), plus the
// Jinja chat template, which some loaders render (CVE-2024-34359).

type ggufInfo struct {
	Version   uint32
	Tensors   uint64
	KVs       uint64
	Arch      string
	Name      string
	FileType  int64
	Templates map[string]string // key -> template (truncated at 1 MiB)
	Problems  []string
	Unchecked int // tensors with a ggml type unknown to the size table
}

// ggml type -> (block size, bytes per block).
var ggmlTypes = map[uint32][2]uint64{
	0: {1, 4}, 1: {1, 2}, 2: {32, 18}, 3: {32, 20}, 6: {32, 22}, 7: {32, 24}, 8: {32, 34}, 9: {32, 36},
	10: {256, 84}, 11: {256, 110}, 12: {256, 144}, 13: {256, 176}, 14: {256, 210}, 15: {256, 292},
	16: {256, 66}, 17: {256, 74}, 18: {256, 98}, 19: {256, 50}, 20: {32, 18}, 21: {256, 110},
	22: {256, 82}, 23: {256, 136}, 24: {1, 1}, 25: {1, 2}, 26: {1, 4}, 27: {1, 8}, 28: {1, 8},
	29: {256, 56}, 30: {1, 2}, 34: {256, 54}, 35: {256, 66}, 39: {32, 17},
}

type countReader struct {
	r *bufio.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

func (c *countReader) u32() (uint32, error) {
	var b [4]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint32(b[:]), nil
}

func (c *countReader) u64() (uint64, error) {
	var b [8]byte
	if _, err := io.ReadFull(c, b[:]); err != nil {
		return 0, err
	}
	return binary.LittleEndian.Uint64(b[:]), nil
}

func (c *countReader) skip(n uint64) error {
	_, err := io.CopyN(io.Discard, c, int64(n))
	return err
}

var errGGUFTrunc = errors.New("truncated")

func parseGGUF(r io.Reader, size int64) *ggufInfo {
	cr := &countReader{r: bufio.NewReaderSize(r, 1<<20)}
	g := &ggufInfo{FileType: -1, Templates: map[string]string{}}
	bad := func(f string, a ...any) *ggufInfo {
		g.Problems = append(g.Problems, fmt.Sprintf(f, a...))
		return g
	}
	var magic [4]byte
	if _, err := io.ReadFull(cr, magic[:]); err != nil || string(magic[:]) != "GGUF" {
		return bad("missing GGUF magic")
	}
	v, err := cr.u32()
	if err != nil {
		return bad("truncated header")
	}
	g.Version = v
	if v < 2 || v > 3 {
		if v == 1 {
			return g // legacy layout (32-bit counts); not checked further
		}
		return bad("unsupported GGUF version %d", v)
	}
	if g.Tensors, err = cr.u64(); err != nil {
		return bad("truncated header")
	}
	if g.KVs, err = cr.u64(); err != nil {
		return bad("truncated header")
	}
	if g.Tensors > uint64(size)/8 || g.Tensors > 1<<24 {
		return bad("implausible tensor count %d for a %d-byte file", g.Tensors, size)
	}
	if g.KVs > uint64(size)/8 || g.KVs > 1<<20 {
		return bad("implausible metadata count %d", g.KVs)
	}
	remaining := func() uint64 {
		if cr.n >= size {
			return 0
		}
		return uint64(size - cr.n)
	}
	readStr := func(keep uint64) (string, error) {
		n, err := cr.u64()
		if err != nil {
			return "", errGGUFTrunc
		}
		if n > remaining() {
			return "", fmt.Errorf("string length %d exceeds the file", n)
		}
		if n > keep {
			b := make([]byte, keep)
			if _, err := io.ReadFull(cr, b); err != nil {
				return "", errGGUFTrunc
			}
			return string(b), cr.skip(n - keep)
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(cr, b); err != nil {
			return "", errGGUFTrunc
		}
		return string(b), nil
	}
	scalar := map[uint32]uint64{0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
	alignment := uint64(32)
	var readVal func(key string, typ uint32, depth int) error
	readVal = func(key string, typ uint32, depth int) error {
		if sz, ok := scalar[typ]; ok {
			var b [8]byte
			if _, err := io.ReadFull(cr, b[:sz]); err != nil {
				return errGGUFTrunc
			}
			val := binary.LittleEndian.Uint64(b[:])
			switch key {
			case "general.alignment":
				if typ == 4 {
					alignment = val
				}
			case "general.file_type":
				g.FileType = int64(val)
			}
			return nil
		}
		switch typ {
		case 8:
			keep := uint64(0)
			if key == "general.architecture" || key == "general.name" {
				keep = 256
			} else if strings.HasPrefix(key, "tokenizer.chat_template") {
				keep = 1 << 20
			}
			s, err := readStr(keep)
			if err != nil {
				return err
			}
			switch {
			case key == "general.architecture":
				g.Arch = s
			case key == "general.name":
				g.Name = s
			case strings.HasPrefix(key, "tokenizer.chat_template"):
				g.Templates[key] = s
			}
			return nil
		case 9:
			if depth > 2 {
				return errors.New("nested arrays too deep")
			}
			et, err := cr.u32()
			if err != nil {
				return errGGUFTrunc
			}
			n, err := cr.u64()
			if err != nil {
				return errGGUFTrunc
			}
			if n > remaining() {
				return fmt.Errorf("array length %d exceeds the file", n)
			}
			if sz, ok := scalar[et]; ok {
				if n*sz > remaining() {
					return fmt.Errorf("array of %d elements exceeds the file", n)
				}
				return cr.skip(n * sz)
			}
			for i := uint64(0); i < n; i++ {
				if err := readVal("", et, depth+1); err != nil {
					return err
				}
			}
			return nil
		}
		return fmt.Errorf("unknown metadata value type %d", typ)
	}
	for i := uint64(0); i < g.KVs; i++ {
		key, err := readStr(64 << 10)
		if err != nil {
			return bad("metadata #%d: %v", i, err)
		}
		typ, err := cr.u32()
		if err != nil {
			return bad("metadata %q: truncated", key)
		}
		if err := readVal(key, typ, 0); err != nil {
			return bad("metadata %q: %v", key, err)
		}
	}
	if alignment == 0 || alignment&(alignment-1) != 0 {
		return bad("general.alignment %d is not a power of two", alignment)
	}
	type tinfo struct {
		name   string
		ne     uint64
		ne0    uint64
		typ    uint32
		offset uint64
	}
	tensors := make([]tinfo, 0, min(g.Tensors, 1<<16))
	for i := uint64(0); i < g.Tensors; i++ {
		name, err := readStr(256)
		if err != nil {
			return bad("tensor #%d: %v", i, err)
		}
		nd, err := cr.u32()
		if err != nil {
			return bad("tensor %q: truncated", name)
		}
		if nd == 0 || nd > 4 {
			return bad("tensor %q: %d dimensions (max 4)", name, nd)
		}
		ne := uint64(1)
		var ne0 uint64
		for d := uint32(0); d < nd; d++ {
			x, err := cr.u64()
			if err != nil {
				return bad("tensor %q: truncated", name)
			}
			if d == 0 {
				ne0 = x
			}
			if x != 0 && ne > (1<<62)/x {
				return bad("tensor %q: element count overflows", name)
			}
			ne *= x
		}
		typ, err := cr.u32()
		if err != nil {
			return bad("tensor %q: truncated", name)
		}
		off, err := cr.u64()
		if err != nil {
			return bad("tensor %q: truncated", name)
		}
		tensors = append(tensors, tinfo{name, ne, ne0, typ, off})
	}
	dataStart := (uint64(cr.n) + alignment - 1) / alignment * alignment
	if dataStart > uint64(size) {
		return bad("tensor data starts past the end of the file")
	}
	dataLen := uint64(size) - dataStart
	for _, t := range tensors {
		if t.offset%alignment != 0 {
			return bad("tensor %q: offset %d not aligned to %d", t.name, t.offset, alignment)
		}
		bs, ok := ggmlTypes[t.typ]
		if !ok {
			g.Unchecked++
			if t.offset > dataLen {
				return bad("tensor %q: offset past the end of the file", t.name)
			}
			continue
		}
		if t.ne0%bs[0] != 0 {
			return bad("tensor %q: row size %d not a multiple of block size %d", t.name, t.ne0, bs[0])
		}
		n := t.ne / bs[0] * bs[1]
		if t.offset > dataLen || n > dataLen-t.offset {
			return bad("tensor %q: data [%d, +%d) extends past the end of the file", t.name, t.offset, n)
		}
	}
	return g
}

func (g *ggufInfo) details() string {
	parts := []string{fmt.Sprintf("GGUF v%d", g.Version)}
	if g.Arch != "" {
		parts = append(parts, "arch "+g.Arch)
	}
	if g.Version >= 2 {
		parts = append(parts, fmt.Sprintf("%d tensors", g.Tensors))
	}
	if g.FileType >= 0 {
		parts = append(parts, fmt.Sprintf("file_type %d", g.FileType))
	}
	if n := len(g.Templates); n > 0 {
		parts = append(parts, fmt.Sprintf("%d chat template(s)", n))
	}
	return strings.Join(parts, ", ")
}

type tmplHit struct {
	key, label string
	fail       bool
}

var (
	tmplDunder = regexp.MustCompile(`__[A-Za-z_]+__`)
	tmplExec   = regexp.MustCompile(`\b(os|subprocess|sys|builtins|importlib)\s*\.|\b(popen|eval|exec|system|__import__)\s*\(`)
	tmplAttr   = regexp.MustCompile(`\|\s*attr\b|\battr\s*\(|\bself\._`)
)

// checkTemplate flags Jinja server-side template injection gadgets.
// Legitimate chat templates never touch dunder attributes.
func checkTemplate(key, t string) []tmplHit {
	var hits []tmplHit
	if m := tmplDunder.FindString(t); m != "" {
		hits = append(hits, tmplHit{key, "dunder attribute " + m, true})
	}
	if m := tmplExec.FindString(t); m != "" {
		hits = append(hits, tmplHit{key, "code-execution call " + strings.TrimSpace(m), true})
	}
	if m := tmplAttr.FindString(t); m != "" && len(hits) == 0 {
		hits = append(hits, tmplHit{key, "attribute traversal " + strings.TrimSpace(m), false})
	}
	return hits
}
