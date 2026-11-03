package models

import (
	"bytes"
	"reflect"
	"testing"
)

func TestScanPickleGlobals(t *testing.T) {
	cases := []struct {
		name  string
		in    []byte
		want  []string
		proto int
	}{
		{"proto2 GLOBAL", pickleOsSystem, []string{"os.system"}, 2},
		{"proto4 STACK_GLOBAL+memo", pickleStackGlobal, []string{"builtins.eval"}, 4},
		{"torch safe", pickleTorchSafe, []string{"torch._utils._rebuild_tensor_v2", "collections.OrderedDict"}, 2},
		{"proto0", pickleProto0, []string{"subprocess.Popen"}, 0},
		{"data only", pickleData, nil, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := ScanPickle(bytes.NewReader(c.in), false, 1<<20)
			if s.Err != nil {
				t.Fatalf("err: %v", s.Err)
			}
			if !reflect.DeepEqual(s.Globals, c.want) {
				t.Fatalf("globals = %q, want %q", s.Globals, c.want)
			}
			if s.Pickles != 1 || s.Proto != c.proto {
				t.Fatalf("pickles=%d proto=%d", s.Pickles, s.Proto)
			}
		})
	}
}

func TestScanPickleMultiAndTrailing(t *testing.T) {
	two := append(append([]byte{}, pickleData...), pickleOsSystem...)
	s := ScanPickle(bytes.NewReader(two), true, 1<<20)
	if s.Pickles != 2 || len(s.Globals) != 1 || s.Globals[0] != "os.system" {
		t.Fatalf("multi: %+v", s)
	}
	// legacy torch files carry raw storage bytes after the pickles
	junk := append(append([]byte{}, pickleData...), 0xff, 0x00, 0x13)
	if s := ScanPickle(bytes.NewReader(junk), true, 1<<20); s.Err != nil || s.Pickles != 1 {
		t.Fatalf("trailing data: %+v", s)
	}
}

func TestScanPickleRejectsAndTruncates(t *testing.T) {
	if s := ScanPickle(bytes.NewReader([]byte("hello world")), false, 1<<20); s.Err == nil {
		t.Fatal("text accepted as pickle")
	}
	// truncated after the GLOBAL: the import is still reported
	s := ScanPickle(bytes.NewReader(pickleOsSystem[:15]), false, 1<<20)
	if s.Err == nil || len(s.Globals) != 1 {
		t.Fatalf("truncated: %+v", s)
	}
	// BINGET of an unknown memo slot must not panic
	ScanPickle(bytes.NewReader([]byte("\x80\x04h\x07h\x08\x93.")), false, 1<<20)
	// huge declared lengths must not allocate
	ScanPickle(bytes.NewReader([]byte("\x80\x04\x8d\xff\xff\xff\xff\xff\xff\xff\x7f")), false, 1<<20)
}

func TestClassifyImport(t *testing.T) {
	for g, want := range map[string]string{
		"os.system":                          ImportDangerous,
		"posix.system":                       ImportDangerous,
		"builtins.exec":                      ImportDangerous,
		"__builtin__.eval":                   ImportDangerous,
		"builtins.getattr":                   ImportDangerous,
		"subprocess.Popen":                   ImportDangerous,
		"torch.hub.load":                     ImportDangerous,
		"foo.__reduce__":                     ImportDangerous,
		"torch._utils._rebuild_tensor_v2":    ImportSafe,
		"torch.FloatStorage":                 ImportSafe,
		"collections.OrderedDict":            ImportSafe,
		"numpy.core.multiarray._reconstruct": ImportSafe,
		"builtins.set":                       ImportSafe,
		"mylib.layers.Block":                 ImportUnknown,
	} {
		if got := ClassifyImport(g); got != want {
			t.Errorf("%s: %s, want %s", g, got, want)
		}
	}
}
