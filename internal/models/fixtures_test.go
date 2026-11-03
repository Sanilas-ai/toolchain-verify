package models

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sanilas-ai/toolchain-verify/internal/findings"
)

// Tiny hand-built fixtures. Pickles are written opcode by opcode; nothing
// here is ever unpickled.

// proto 2: os.system("id")
var pickleOsSystem = []byte("\x80\x02cos\nsystem\nq\x00X\x02\x00\x00\x00idq\x01\x85q\x02Rq\x03.")

// proto 4: STACK_GLOBAL from memoized strings, then again through BINGET.
var pickleStackGlobal = []byte("\x80\x04\x8c\x08builtins\x94\x8c\x04eval\x94\x93\x94h\x00h\x01\x93\x8c\x011\x85R.")

// proto 2: a torch-like safe rebuild call.
var pickleTorchSafe = []byte("\x80\x02ctorch._utils\n_rebuild_tensor_v2\nq\x00)Rq\x01ccollections\nOrderedDict\n)R.")

// proto 0 text pickle.
var pickleProto0 = []byte("csubprocess\nPopen\n(S'id'\ntR.")

// unknown import.
var pickleUnknown = []byte("\x80\x02cmylib.layers\nBlock\n)R.")

// data only: {"a": 1}
var pickleData = []byte("\x80\x02}q\x00X\x01\x00\x00\x00aK\x01s.")

func write(t *testing.T, p string, b []byte) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func sum(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }

func safetensors(t *testing.T, header map[string]any, data []byte) []byte {
	t.Helper()
	h, err := json.Marshal(header)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, uint64(len(h)))
	b.Write(h)
	b.Write(data)
	return b.Bytes()
}

type ggufKV struct {
	key string
	val any // string or uint32
}

type ggufTensor struct {
	name   string
	dims   []uint64
	typ    uint32
	offset uint64
}

func ggufStr(b *bytes.Buffer, s string) {
	binary.Write(b, binary.LittleEndian, uint64(len(s)))
	b.WriteString(s)
}

// gguf writes a GGUF v3 file; nTensors overrides the declared tensor count
// when > 0.
func gguf(kvs []ggufKV, tensors []ggufTensor, data int, nTensors uint64) []byte {
	var b bytes.Buffer
	b.WriteString("GGUF")
	binary.Write(&b, binary.LittleEndian, uint32(3))
	if nTensors == 0 {
		nTensors = uint64(len(tensors))
	}
	binary.Write(&b, binary.LittleEndian, nTensors)
	binary.Write(&b, binary.LittleEndian, uint64(len(kvs)))
	for _, kv := range kvs {
		ggufStr(&b, kv.key)
		switch v := kv.val.(type) {
		case string:
			binary.Write(&b, binary.LittleEndian, uint32(8))
			ggufStr(&b, v)
		case uint32:
			binary.Write(&b, binary.LittleEndian, uint32(4))
			binary.Write(&b, binary.LittleEndian, v)
		}
	}
	for _, ti := range tensors {
		ggufStr(&b, ti.name)
		binary.Write(&b, binary.LittleEndian, uint32(len(ti.dims)))
		for _, d := range ti.dims {
			binary.Write(&b, binary.LittleEndian, d)
		}
		binary.Write(&b, binary.LittleEndian, ti.typ)
		binary.Write(&b, binary.LittleEndian, ti.offset)
	}
	for b.Len()%32 != 0 {
		b.WriteByte(0)
	}
	b.Write(make([]byte, data))
	return b.Bytes()
}

func zipFile(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for n, c := range files {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		w.Write(c)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func gz(b []byte) []byte {
	var o bytes.Buffer
	w := gzip.NewWriter(&o)
	w.Write(b)
	w.Close()
	return o.Bytes()
}

func npy(descr string, payload []byte) []byte {
	h := "{'descr': " + descr + ", 'fortran_order': False, 'shape': (2,), }"
	for (10+len(h)+1)%64 != 0 {
		h += " "
	}
	h += "\n"
	var b bytes.Buffer
	b.WriteString("\x93NUMPY\x01\x00")
	binary.Write(&b, binary.LittleEndian, uint16(len(h)))
	b.WriteString(h)
	b.Write(payload)
	return b.Bytes()
}

func noEnv(string) string { return "" }

func noScanners(string) (string, error) { return "", os.ErrNotExist }

// scan runs the models scan over dir with no Ollama and no external scanners.
func scan(t *testing.T, pol *Policy, paths ...string) *Report {
	t.Helper()
	if pol == nil {
		pol = &Policy{}
	}
	rep, err := Run(pol, Options{Paths: paths, NoOllama: true, Getenv: noEnv, LookPath: noScanners})
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func find(rep *Report, rule, pathSub string) *findings.Finding {
	for i, f := range rep.Findings {
		if f.Rule == rule && strings.Contains(f.Path, pathSub) {
			return &rep.Findings[i]
		}
	}
	return nil
}

func artifact(rep *Report, base string) *Artifact {
	for i, a := range rep.Artifacts {
		if filepath.Base(a.Path) == base {
			return &rep.Artifacts[i]
		}
	}
	return nil
}

func dump(rep *Report) string {
	var s []string
	for _, f := range rep.Findings {
		s = append(s, f.Severity+" "+f.Rule+" "+f.Path+": "+f.Message)
	}
	return strings.Join(s, "\n")
}
