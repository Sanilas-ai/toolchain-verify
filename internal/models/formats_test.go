package models

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestSafetensorsChecks(t *testing.T) {
	ok := safetensors(t, map[string]any{
		"__metadata__": map[string]string{"format": "pt"},
		"w":            map[string]any{"dtype": "F32", "shape": []int{2}, "data_offsets": []int{0, 8}},
		"b":            map[string]any{"dtype": "F16", "shape": []int{2, 2}, "data_offsets": []int{8, 16}},
	}, make([]byte, 16))
	if d, probs := checkSafetensors(bytes.NewReader(ok), int64(len(ok))); len(probs) != 0 || !strings.Contains(d, "2 tensors") {
		t.Fatalf("valid: %q %v", d, probs)
	}
	bad := map[string]struct {
		hdr  map[string]any
		data int
		want string
	}{
		"out of bounds": {map[string]any{"w": map[string]any{"dtype": "F32", "shape": []int{4}, "data_offsets": []int{0, 16}}}, 8, ""},
		"size mismatch": {map[string]any{"w": map[string]any{"dtype": "F32", "shape": []int{4}, "data_offsets": []int{0, 8}}}, 8, ""},
		"hole":          {map[string]any{"w": map[string]any{"dtype": "U8", "shape": []int{4}, "data_offsets": []int{4, 8}}}, 8, ""},
		"bad dtype":     {map[string]any{"w": map[string]any{"dtype": "WAT", "shape": []int{1}, "data_offsets": []int{0, 1}}}, 1, ""},
	}
	for name, c := range bad {
		b := safetensors(t, c.hdr, make([]byte, c.data))
		if _, probs := checkSafetensors(bytes.NewReader(b), int64(len(b))); len(probs) == 0 {
			t.Errorf("%s: not flagged", name)
		}
	}
	// header length larger than the file
	huge := append([]byte{0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0}, []byte("{}")...)
	if _, probs := checkSafetensors(bytes.NewReader(huge), int64(len(huge))); len(probs) == 0 {
		t.Error("huge header length not flagged")
	}
}

func TestGGUF(t *testing.T) {
	kvs := []ggufKV{{"general.architecture", "llama"}, {"general.alignment", uint32(32)},
		{"tokenizer.chat_template", "{% for m in messages %}{{ m['role'] }}: {{ m['content'] }}{% endfor %}"}}
	// F32 (type 0) 8 elements = 32 bytes, then F16 (type 1) 16 elements = 32 bytes
	tensors := []ggufTensor{{"a", []uint64{8}, 0, 0}, {"b", []uint64{4, 4}, 1, 32}}
	ok := gguf(kvs, tensors, 64, 0)
	g := parseGGUF(bytes.NewReader(ok), int64(len(ok)))
	if len(g.Problems) != 0 || g.Version != 3 || g.Tensors != 2 || g.Arch != "llama" || len(g.Templates) != 1 {
		t.Fatalf("valid: %+v", g)
	}
	past := gguf(kvs, tensors, 40, 0)
	if g := parseGGUF(bytes.NewReader(past), int64(len(past))); len(g.Problems) == 0 {
		t.Error("tensor past EOF not flagged")
	}
	lie := gguf(kvs, tensors, 64, 1<<40)
	if g := parseGGUF(bytes.NewReader(lie), int64(len(lie))); len(g.Problems) == 0 {
		t.Error("absurd tensor count not flagged")
	}
	trunc := ok[:30]
	if g := parseGGUF(bytes.NewReader(trunc), int64(len(trunc))); len(g.Problems) == 0 {
		t.Error("truncated header not flagged")
	}
	evil := gguf([]ggufKV{{"tokenizer.chat_template", "{{ ''.__class__.__mro__[1].__subclasses__() }}"}}, nil, 0, 0)
	g = parseGGUF(bytes.NewReader(evil), int64(len(evil)))
	if tpl := g.Templates["tokenizer.chat_template"]; len(checkTemplate("tokenizer.chat_template", tpl)) == 0 {
		t.Error("SSTI template not flagged")
	}
}

func TestCheckTemplateNoFalsePositives(t *testing.T) {
	for _, tpl := range []string{
		"{%- if messages[0]['role'] == 'system' %}{{ messages[0]['content'] }}{% endif %}",
		"{{ bos_token }}{% for message in messages %}{{ '<|im_start|>' + message.role }}{% endfor %}",
		"{{- raise_exception('Conversation roles must alternate') }}",
	} {
		if hits := checkTemplate("tokenizer.chat_template", tpl); len(hits) != 0 {
			t.Errorf("false positive %v on %q", hits, tpl)
		}
	}
}

func TestSniffAndPickleLike(t *testing.T) {
	dir := t.TempDir()
	st := safetensors(t, map[string]any{"w": map[string]any{"dtype": "U8", "shape": []int{1}, "data_offsets": []int{0, 1}}}, []byte{1})
	cases := map[string]struct {
		data   []byte
		format string
		pickle bool
	}{
		"a.pkl":             {pickleOsSystem, FmtPickle, true},
		"pytorch_model.bin": {st, FmtSafetensors, false},
		"old.bin":           {pickleTorchSafe, FmtPickle, true},
		"m.pt":              {zipFile(t, map[string][]byte{"archive/data.pkl": pickleTorchSafe}), FmtTorchZip, true},
		"m.gguf":            {gguf(nil, nil, 0, 0), FmtGGUF, false},
		"m.joblib":          {gz(pickleData), "gzip", true},
		"arr.npy":           {npy("'<f4'", make([]byte, 8)), FmtNpy, false},
		"x.pdiparams.info":  {pickleData, FmtPickle, true},
		"ct2.bin":           {[]byte{0x05, 0, 0, 0, 0x10, 0x20}, FmtUnknown, false},
	}
	for name, c := range cases {
		p := write(t, filepath.Join(dir, name), c.data)
		f, err := Sniff(p)
		if err != nil {
			t.Fatal(err)
		}
		if f != c.format || PickleLike(f, name) != c.pickle {
			t.Errorf("%s: format %s pickle %v, want %s %v", name, f, PickleLike(f, name), c.format, c.pickle)
		}
	}
	if IsArtifactName("._m.gguf") || !IsArtifactName("x.pdiparams.info") || IsArtifactName("README.md") {
		t.Error("IsArtifactName")
	}
}
