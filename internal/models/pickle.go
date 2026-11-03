package models

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Static pickle analysis. The opcode stream is walked with a model of the
// unpickler's stack and memo so that every global the stream would import
// (GLOBAL, INST, STACK_GLOBAL, EXT*) is recovered, including names built
// from memoized strings. Nothing is ever unpickled.

// PickleScan is the result of scanning one pickle stream (or several
// concatenated ones, as in legacy torch files).
type PickleScan struct {
	Globals []string // "module.name" in first-seen order
	Pickles int      // complete pickles (STOP reached)
	Proto   int      // highest PROTO seen
	Err     error    // parse error; Globals found before it are still valid
}

var errNotPickle = errors.New("not a pickle stream")

const (
	maxPickleStack = 1 << 20
	maxPickleMemo  = 1 << 22
	maxPickles     = 32
	maxStrKeep     = 512 // longer strings are never module/class names
)

type pval struct {
	s     string
	isStr bool
	mark  bool
}

// ScanPickle walks the opcode stream in r. When multi is true it continues
// with the next pickle after STOP if one follows (legacy torch format).
// limit bounds the bytes read (0 = 4 GiB).
func ScanPickle(r io.Reader, multi bool, limit int64) PickleScan {
	if limit <= 0 {
		limit = 4 << 30
	}
	lr := &io.LimitedReader{R: r, N: limit}
	br := bufio.NewReaderSize(lr, 64<<10)
	var res PickleScan
	seen := map[string]bool{}
	addGlobal := func(mod, name string) {
		g := strings.TrimSpace(mod) + "." + strings.TrimSpace(name)
		if !seen[g] {
			seen[g] = true
			res.Globals = append(res.Globals, g)
		}
	}
	for res.Pickles < maxPickles {
		err := scanOne(br, &res, addGlobal)
		if err != nil && res.Pickles > 0 {
			// data after a complete pickle (legacy torch storages): the
			// globals seen so far are kept, the rest is not a pickle.
			return res
		}
		if err != nil {
			if res.Pickles == 0 && len(res.Globals) == 0 && errors.Is(err, errNotPickle) {
				res.Err = errNotPickle
			} else if lr.N <= 0 {
				res.Err = fmt.Errorf("stopped after %d bytes (scan limit)", limit)
			} else {
				res.Err = err
			}
			return res
		}
		res.Pickles++
		if !multi {
			break
		}
		b, err := br.Peek(1)
		if err != nil || b[0] != 0x80 {
			break
		}
	}
	return res
}

func scanOne(br *bufio.Reader, res *PickleScan, addGlobal func(string, string)) error {
	var stack []pval
	memo := map[uint64]pval{}
	first := true
	push := func(v pval) error {
		if len(stack) >= maxPickleStack {
			return errors.New("pickle stack too deep")
		}
		stack = append(stack, v)
		return nil
	}
	pop := func(n int) error {
		if len(stack) < n {
			return errors.New("pickle stack underflow")
		}
		for _, v := range stack[len(stack)-n:] {
			if v.mark {
				return errors.New("pickle mark where a value was expected")
			}
		}
		stack = stack[:len(stack)-n]
		return nil
	}
	popMark := func() error {
		for i := len(stack) - 1; i >= 0; i-- {
			if stack[i].mark {
				stack = stack[:i]
				return nil
			}
		}
		return errors.New("pickle mark not found")
	}
	put := func(idx uint64) error {
		if len(stack) == 0 {
			return errors.New("memo put on empty stack")
		}
		if len(memo) >= maxPickleMemo {
			return errors.New("pickle memo too large")
		}
		memo[idx] = stack[len(stack)-1]
		return nil
	}
	get := func(idx uint64) error {
		v, ok := memo[idx]
		if !ok {
			return fmt.Errorf("memo key %d not defined", idx)
		}
		return push(v)
	}
	str := func(b []byte) pval {
		if len(b) > maxStrKeep {
			return pval{}
		}
		return pval{s: string(b), isStr: true}
	}
	for {
		op, err := br.ReadByte()
		if err != nil {
			if first {
				return errNotPickle
			}
			return fmt.Errorf("truncated pickle: %w", err)
		}
		if first && !validFirstOp(op) {
			return errNotPickle
		}
		first = false
		switch op {
		case '.': // STOP
			return pop(1)
		case 0x80: // PROTO
			b, err := br.ReadByte()
			if err != nil {
				return err
			}
			if b > 5 {
				return fmt.Errorf("unsupported pickle protocol %d", b)
			}
			if int(b) > res.Proto {
				res.Proto = int(b)
			}
		case 0x95: // FRAME
			if _, err := readN(br, 8); err != nil {
				return err
			}
		case '(': // MARK
			if err := push(pval{mark: true}); err != nil {
				return err
			}
		case 'I', 'L', 'F': // INT, LONG, FLOAT (text)
			if _, err := readLine(br); err != nil {
				return err
			}
			if err := push(pval{}); err != nil {
				return err
			}
		case 'S': // STRING 'quoted'
			l, err := readLine(br)
			if err != nil {
				return err
			}
			s := strings.TrimSpace(string(l))
			if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
				s = s[1 : len(s)-1]
			}
			if err := push(str([]byte(s))); err != nil {
				return err
			}
		case 'V': // UNICODE (raw-unicode-escape, newline terminated)
			l, err := readLine(br)
			if err != nil {
				return err
			}
			if err := push(str(l)); err != nil {
				return err
			}
		case 'P': // PERSID
			if _, err := readLine(br); err != nil {
				return err
			}
			if err := push(pval{}); err != nil {
				return err
			}
		case 'p', 'g': // PUT, GET (text index)
			l, err := readLine(br)
			if err != nil {
				return err
			}
			idx, err := strconv.ParseUint(strings.TrimSpace(string(l)), 10, 64)
			if err != nil {
				return fmt.Errorf("bad memo index %q", l)
			}
			if op == 'p' {
				err = put(idx)
			} else {
				err = get(idx)
			}
			if err != nil {
				return err
			}
		case 'c', 'i': // GLOBAL, INST: "module\nname\n"
			mod, err := readLine(br)
			if err != nil {
				return err
			}
			name, err := readLine(br)
			if err != nil {
				return err
			}
			addGlobal(string(mod), string(name))
			if op == 'i' {
				if err := popMark(); err != nil {
					return err
				}
			}
			if err := push(pval{}); err != nil {
				return err
			}
		case 'J': // BININT
			if err := skipPush(br, 4, push); err != nil {
				return err
			}
		case 'K': // BININT1
			if err := skipPush(br, 1, push); err != nil {
				return err
			}
		case 'M': // BININT2
			if err := skipPush(br, 2, push); err != nil {
				return err
			}
		case 'G': // BINFLOAT
			if err := skipPush(br, 8, push); err != nil {
				return err
			}
		case 0x8a: // LONG1
			n, err := br.ReadByte()
			if err != nil {
				return err
			}
			if err := skipPush(br, int64(n), push); err != nil {
				return err
			}
		case 0x8b: // LONG4
			n, err := readLen(br, 4)
			if err != nil {
				return err
			}
			if err := skipPush(br, n, push); err != nil {
				return err
			}
		case 'U', 'C', 0x8c: // SHORT_BINSTRING, SHORT_BINBYTES, SHORT_BINUNICODE
			n, err := br.ReadByte()
			if err != nil {
				return err
			}
			if err := strPush(br, int64(n), op != 'C', push, str); err != nil {
				return err
			}
		case 'T', 'X', 'B': // BINSTRING, BINUNICODE, BINBYTES (4-byte len)
			n, err := readLen(br, 4)
			if err != nil {
				return err
			}
			if err := strPush(br, n, op != 'B', push, str); err != nil {
				return err
			}
		case 0x8d, 0x8e, 0x96: // BINUNICODE8, BINBYTES8, BYTEARRAY8
			n, err := readLen(br, 8)
			if err != nil {
				return err
			}
			if err := strPush(br, n, op == 0x8d, push, str); err != nil {
				return err
			}
		case 'N', 0x88, 0x89, ')', ']', '}', 0x8f, 0x97: // NONE, TRUE, FALSE, EMPTY_*, NEXT_BUFFER
			if err := push(pval{}); err != nil {
				return err
			}
		case 0x98: // READONLY_BUFFER
		case 'h', 'q': // BINGET, BINPUT
			b, err := br.ReadByte()
			if err != nil {
				return err
			}
			if op == 'h' {
				err = get(uint64(b))
			} else {
				err = put(uint64(b))
			}
			if err != nil {
				return err
			}
		case 'j', 'r': // LONG_BINGET, LONG_BINPUT
			n, err := readLen(br, 4)
			if err != nil {
				return err
			}
			if op == 'j' {
				err = get(uint64(n))
			} else {
				err = put(uint64(n))
			}
			if err != nil {
				return err
			}
		case 0x94: // MEMOIZE
			if err := put(uint64(len(memo))); err != nil {
				return err
			}
		case 0x82, 0x83, 0x84: // EXT1, EXT2, EXT4
			n := map[byte]int{0x82: 1, 0x83: 2, 0x84: 4}[op]
			b, err := readN(br, n)
			if err != nil {
				return err
			}
			var code uint32
			for i := len(b) - 1; i >= 0; i-- {
				code = code<<8 | uint32(b[i])
			}
			addGlobal("copyreg", fmt.Sprintf("extension_%d", code))
			if err := push(pval{}); err != nil {
				return err
			}
		case 0x93: // STACK_GLOBAL
			if len(stack) < 2 {
				return errors.New("pickle stack underflow")
			}
			m, n := stack[len(stack)-2], stack[len(stack)-1]
			mod, name := "?", "?"
			if m.isStr {
				mod = m.s
			}
			if n.isStr {
				name = n.s
			}
			addGlobal(mod, name)
			if err := pop(2); err != nil {
				return err
			}
			if err := push(pval{}); err != nil {
				return err
			}
		case 't', 'l', 'd', 0x91, 'o': // TUPLE, LIST, DICT, FROZENSET, OBJ
			if err := popMark(); err != nil {
				return err
			}
			if err := push(pval{}); err != nil {
				return err
			}
		case 'e', 'u', 0x90, '1': // APPENDS, SETITEMS, ADDITEMS, POP_MARK
			if err := popMark(); err != nil {
				return err
			}
		case '0', 'a', 'b': // POP, APPEND, BUILD
			if err := pop(1); err != nil {
				return err
			}
		case 's': // SETITEM
			if err := pop(2); err != nil {
				return err
			}
		case '2': // DUP
			if len(stack) == 0 {
				return errors.New("pickle stack underflow")
			}
			if err := push(stack[len(stack)-1]); err != nil {
				return err
			}
		case 0x85, 'Q': // TUPLE1, BINPERSID
			if err := pop(1); err != nil {
				return err
			}
			if err := push(pval{}); err != nil {
				return err
			}
		case 0x86, 'R', 0x81: // TUPLE2, REDUCE, NEWOBJ
			if err := pop(2); err != nil {
				return err
			}
			if err := push(pval{}); err != nil {
				return err
			}
		case 0x87, 0x92: // TUPLE3, NEWOBJ_EX
			if err := pop(3); err != nil {
				return err
			}
			if err := push(pval{}); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unknown pickle opcode 0x%02x", op)
		}
	}
}

// validFirstOp rejects streams that cannot be a pickle so that random
// binary files are not reported as broken pickles.
func validFirstOp(op byte) bool {
	switch op {
	case 0x80, '(', ']', '}', ')', 'c', 'N', 'I', 'L', 'F', 'S', 'V', 'K', 'J', 'M', 'X', 'U', 'T', 'G', 0x88, 0x89, 0x8c, 0x95, 'l', 'd', 't':
		return true
	}
	return false
}

func readN(br *bufio.Reader, n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(br, b)
	return b, err
}

func readLen(br *bufio.Reader, n int) (int64, error) {
	b, err := readN(br, n)
	if err != nil {
		return 0, err
	}
	var v uint64
	if n == 4 {
		v = uint64(binary.LittleEndian.Uint32(b))
	} else {
		v = binary.LittleEndian.Uint64(b)
	}
	if v > 1<<40 {
		return 0, fmt.Errorf("implausible pickle length %d", v)
	}
	return int64(v), nil
}

func readLine(br *bufio.Reader) ([]byte, error) {
	var out []byte
	for {
		chunk, err := br.ReadSlice('\n')
		out = append(out, chunk...)
		if err == nil {
			return out[:len(out)-1], nil
		}
		if err != bufio.ErrBufferFull {
			return nil, err
		}
		if len(out) > 1<<16 {
			return nil, errors.New("pickle text argument too long")
		}
	}
}

func skipPush(br *bufio.Reader, n int64, push func(pval) error) error {
	if _, err := io.CopyN(io.Discard, br, n); err != nil {
		return err
	}
	return push(pval{})
}

func strPush(br *bufio.Reader, n int64, text bool, push func(pval) error, str func([]byte) pval) error {
	if !text || n > maxStrKeep {
		return skipPush(br, n, push)
	}
	b, err := readN(br, int(n))
	if err != nil {
		return err
	}
	return push(str(b))
}

// Import classes.
const (
	ImportSafe      = "safe"
	ImportDangerous = "dangerous"
	ImportUnknown   = "unknown"
)

// dangerousModules can run code, touch files or the network when a
// global from them is called during unpickling (cf. picklescan).
var dangerousModules = []string{
	"os", "posix", "nt", "subprocess", "sys", "socket", "shutil", "runpy", "pty", "pdb", "bdb",
	"webbrowser", "commands", "importlib", "imp", "zipimport", "pkgutil", "ctypes", "_ctypes",
	"multiprocessing", "asyncio", "code", "codeop", "marshal", "pickle", "_pickle", "cPickle",
	"dill", "cloudpickle", "types", "requests", "urllib", "urllib2", "urllib3", "http", "httplib",
	"ftplib", "smtplib", "telnetlib", "aiohttp", "platform", "signal", "tempfile", "glob",
	"pathlib", "io", "_io", "ssl", "select", "threading", "_thread", "pip", "setuptools",
	"distutils", "venv", "ensurepip", "timeit", "cProfile", "profile", "trace", "sqlite3",
	"torch.hub", "numpy.testing", "numpy.f2py", "_posixsubprocess", "posixpath", "ntpath",
}

var dangerousNames = map[string]bool{
	"builtins.eval": true, "builtins.exec": true, "builtins.execfile": true, "builtins.compile": true,
	"builtins.open": true, "builtins.getattr": true, "builtins.setattr": true, "builtins.delattr": true,
	"builtins.__import__": true, "builtins.globals": true, "builtins.locals": true, "builtins.vars": true,
	"builtins.breakpoint": true, "builtins.input": true, "builtins.apply": true, "builtins.exit": true,
	"builtins.quit": true, "builtins.help": true, "builtins.memoryview": false,
	"operator.attrgetter": true, "operator.methodcaller": true, "operator.itemgetter": false,
	"torch.load": true, "torch.jit.load": true,
}

var safeNames = map[string]bool{
	"collections.OrderedDict": true, "collections.defaultdict": true, "collections.deque": true, "collections.Counter": true,
	"copyreg._reconstructor": true, "_codecs.encode": true,
	"numpy.ndarray": true, "numpy.dtype": true,
	"numpy.core.multiarray._reconstruct": true, "numpy._core.multiarray._reconstruct": true,
	"numpy.core.multiarray.scalar": true, "numpy._core.multiarray.scalar": true,
	"numpy.core.numeric._frombuffer": true, "numpy._core.numeric._frombuffer": true,
	"torch.Size": true, "torch.device": true, "torch.serialization._get_layout": true,
	"torch.nn.parameter.Parameter": true, "torch._tensor._rebuild_from_type_v2": true,
	"torch.storage.UntypedStorage": true, "torch.storage.TypedStorage": true,
}

var safeBuiltins = map[string]bool{
	"set": true, "frozenset": true, "dict": true, "list": true, "tuple": true, "int": true, "float": true,
	"complex": true, "bool": true, "bytes": true, "bytearray": true, "str": true, "slice": true, "range": true, "object": true,
}

var torchDtypes = map[string]bool{
	"float": true, "double": true, "half": true, "bfloat16": true, "float16": true, "float32": true, "float64": true,
	"int": true, "long": true, "short": true, "int8": true, "int16": true, "int32": true, "int64": true,
	"uint8": true, "uint16": true, "uint32": true, "uint64": true, "bool": true, "complex64": true, "complex128": true,
	"qint8": true, "quint8": true, "qint32": true, "float8_e4m3fn": true, "float8_e5m2": true, "strided": true,
	"sparse_coo": true, "contiguous_format": true, "channels_last": true, "preserve_format": true,
}

// ClassifyImport says whether importing global g ("module.name") during
// unpickling is known safe, known dangerous, or unknown.
func ClassifyImport(g string) string {
	i := strings.LastIndex(g, ".")
	if i < 0 {
		return ImportUnknown
	}
	mod, name := g[:i], g[i+1:]
	if mod == "__builtin__" || mod == "__builtins__" {
		mod = "builtins"
	}
	if mod == "copy_reg" {
		mod = "copyreg"
	}
	full := mod + "." + name
	if v, ok := dangerousNames[full]; ok && v {
		return ImportDangerous
	}
	for _, m := range dangerousModules {
		if mod == m || strings.HasPrefix(mod, m+".") {
			return ImportDangerous
		}
	}
	if strings.Contains(name, "__") && name != "__newobj__" && name != "__newobj_ex__" {
		return ImportDangerous // dunder access such as __getattribute__/__globals__
	}
	if mod == "?" || name == "?" {
		return ImportUnknown
	}
	if mod == "builtins" {
		if safeBuiltins[name] {
			return ImportSafe
		}
		return ImportUnknown
	}
	if safeNames[full] {
		return ImportSafe
	}
	if mod == "copyreg" && (name == "__newobj__" || name == "__newobj_ex__") {
		return ImportSafe
	}
	if mod == "torch" && (strings.HasSuffix(name, "Storage") || torchDtypes[name]) {
		return ImportSafe
	}
	if mod == "torch._utils" && strings.HasPrefix(name, "_rebuild_") {
		return ImportSafe
	}
	if mod == "torch.jit._pickle" && (strings.HasPrefix(name, "build_") || name == "restore_type_tag") {
		return ImportSafe
	}
	return ImportUnknown
}
