package models

import (
	"archive/zip"
	"bufio"
	"compress/bzip2"
	"compress/gzip"
	"compress/zlib"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"regexp"
	"sort"
	"strings"
)

// facts are the format-level observations about one file.
type facts struct {
	format    string
	details   string
	pickle    bool     // deserializing it runs pickle
	imports   []string // globals imported by the pickle stream(s)
	partial   string   // why the pickle scan is incomplete
	malformed []string
	templates []tmplHit
	lambda    bool
}

func (f *facts) addScan(where string, s PickleScan) {
	f.pickle = true
	seen := map[string]bool{}
	for _, g := range f.imports {
		seen[g] = true
	}
	for _, g := range s.Globals {
		if !seen[g] {
			seen[g] = true
			f.imports = append(f.imports, g)
		}
	}
	if s.Err != nil && f.partial == "" {
		msg := s.Err.Error()
		for _, g := range s.Globals {
			if strings.HasPrefix(g, "joblib.numpy_pickle.") {
				msg += " (joblib stores numpy arrays inline after the pickle opcodes)"
				break
			}
		}
		if where != "" {
			msg = where + ": " + msg
		}
		f.partial = msg
	}
}

// inspect parses the file at p according to its sniffed format.
func inspect(p string, size int64, maxPickle int64) (*facts, error) {
	fh, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(fh, head)
	head = head[:n]
	if _, err := fh.Seek(0, io.SeekStart); err != nil {
		return nil, err
	}
	fa := &facts{format: SniffHeader(head, size)}
	name := strings.ToLower(p)
	switch fa.format {
	case FmtGGUF:
		g := parseGGUF(fh, size)
		fa.details = g.details()
		fa.malformed = g.Problems
		keys := make([]string, 0, len(g.Templates))
		for k := range g.Templates {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fa.templates = append(fa.templates, checkTemplate(k, g.Templates[k])...)
		}
		if g.Unchecked > 0 {
			fa.details += fmt.Sprintf(", %d tensors of unknown ggml type not size-checked", g.Unchecked)
		}
	case FmtSafetensors:
		fa.details, fa.malformed = checkSafetensors(fh, size)
	case FmtPickle:
		fa.addScan("", ScanPickle(fh, true, maxPickle))
		fa.details = fmt.Sprintf("pickle protocol %d", firstProto(head))
	case FmtNpy:
		fa.details, err = checkNpy(fh, fa, "", maxPickle)
		if err != nil {
			fa.malformed = append(fa.malformed, err.Error())
		}
	case FmtZip:
		checkZip(p, size, fa, maxPickle)
	case FmtGzip, FmtZlib, FmtBzip2:
		if !IsPickleName(name) {
			fa.details = fa.format + "-compressed data"
			break
		}
		var r io.Reader
		switch fa.format {
		case FmtGzip:
			r, err = gzip.NewReader(fh)
		case FmtZlib:
			r, err = zlib.NewReader(fh)
		default:
			r = bzip2.NewReader(fh)
		}
		fa.details = fa.format + "-compressed pickle (joblib style)"
		if err != nil {
			fa.pickle = true
			fa.partial = "cannot decompress: " + err.Error()
			break
		}
		s := ScanPickle(r, true, maxPickle)
		if s.Err == errNotPickle {
			fa.details = fa.format + "-compressed data (not a pickle)"
			break
		}
		fa.addScan("", s)
	case FmtXZ, FmtLZ4:
		if IsPickleName(name) {
			fa.pickle = true
			fa.details = fa.format + "-compressed (joblib style)"
			fa.partial = fa.format + " decompression is not built in; use picklescan/modelscan"
		} else {
			fa.details = fa.format + "-compressed data"
		}
	case FmtHDF5:
		fa.details = "HDF5 (Keras .h5 models can hold Lambda layers; load with safe_mode)"
	case FmtText, FmtUnknown:
		if hasSuffixAny(name, []string{".pkl", ".pickle", ".joblib", ".jbl", ".pdparams", ".pdopt", ".pdiparams.info"}) {
			// protocol 0/1 pickles have no magic number
			s := ScanPickle(fh, true, maxPickle)
			if s.Err != errNotPickle {
				fa.format = FmtPickle
				fa.details = "pickle protocol 0/1"
				fa.addScan("", s)
				break
			}
			fa.pickle = true
			fa.partial = "not a recognizable pickle stream"
		}
		if fa.format == FmtUnknown && strings.HasSuffix(name, ".bin") {
			fa.details = "not pickle, zip, safetensors or GGUF (e.g. CTranslate2 or raw weights)"
		}
		if strings.HasSuffix(name, ".onnx") {
			fa.details = "ONNX (protobuf; not deserialized with pickle)"
		}
	}
	return fa, nil
}

func firstProto(head []byte) int {
	if len(head) >= 2 && head[0] == 0x80 {
		return int(head[1])
	}
	return 0
}

var stDtypeSize = map[string]uint64{
	"BOOL": 1, "U8": 1, "I8": 1, "F8_E4M3": 1, "F8_E5M2": 1, "F8_E8M0": 1, "I16": 2, "U16": 2, "F16": 2, "BF16": 2,
	"I32": 4, "U32": 4, "F32": 4, "I64": 8, "U64": 8, "F64": 8, "C64": 8,
}
var stSubByte = map[string]bool{"F4": true, "F6_E2M3": true, "F6_E3M2": true}

// checkSafetensors validates the JSON header against the spec: offsets
// within the buffer, sizes matching dtype*shape, no overlaps or holes.
func checkSafetensors(r io.Reader, size int64) (string, []string) {
	var hb [8]byte
	if _, err := io.ReadFull(r, hb[:]); err != nil {
		return "", []string{"truncated header"}
	}
	n := binary.LittleEndian.Uint64(hb[:])
	if n > 100<<20 || int64(n)+8 > size {
		return "", []string{fmt.Sprintf("header length %d is implausible for a %d-byte file", n, size)}
	}
	hdr := make([]byte, n)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return "", []string{"truncated header"}
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(hdr, &raw); err != nil {
		return "", []string{"header is not a JSON object: " + err.Error()}
	}
	var problems []string
	if m, ok := raw["__metadata__"]; ok {
		var md map[string]string
		if err := json.Unmarshal(m, &md); err != nil {
			problems = append(problems, "__metadata__ must map strings to strings")
		}
		delete(raw, "__metadata__")
	}
	type span struct {
		name       string
		begin, end uint64
	}
	var spans []span
	dtypes := map[string]bool{}
	buf := uint64(size) - 8 - n
	for name, v := range raw {
		var t struct {
			Dtype   string   `json:"dtype"`
			Shape   []uint64 `json:"shape"`
			Offsets []uint64 `json:"data_offsets"`
		}
		if err := json.Unmarshal(v, &t); err != nil || len(t.Offsets) != 2 {
			problems = append(problems, fmt.Sprintf("tensor %q: bad entry", name))
			continue
		}
		b, e := t.Offsets[0], t.Offsets[1]
		if e < b || e > buf {
			problems = append(problems, fmt.Sprintf("tensor %q: data_offsets [%d, %d] outside the %d-byte buffer", name, b, e, buf))
			continue
		}
		dtypes[t.Dtype] = true
		if es, ok := stDtypeSize[t.Dtype]; ok {
			cnt := uint64(1)
			overflow := false
			for _, d := range t.Shape {
				if d != 0 && cnt > (1<<62)/d {
					overflow = true
				}
				cnt *= d
			}
			if overflow || cnt*es != e-b {
				problems = append(problems, fmt.Sprintf("tensor %q: %s%v needs %d bytes, offsets give %d", name, t.Dtype, t.Shape, cnt*es, e-b))
			}
		} else if !stSubByte[t.Dtype] {
			problems = append(problems, fmt.Sprintf("tensor %q: unknown dtype %q", name, t.Dtype))
		}
		spans = append(spans, span{name, b, e})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].begin < spans[j].begin })
	var pos uint64
	for _, s := range spans {
		if s.begin < pos {
			problems = append(problems, fmt.Sprintf("tensor %q overlaps the previous tensor", s.name))
		} else if s.begin > pos {
			problems = append(problems, fmt.Sprintf("hole of %d bytes before tensor %q", s.begin-pos, s.name))
		}
		if s.end > pos {
			pos = s.end
		}
	}
	if pos != buf && len(spans) > 0 && len(problems) == 0 {
		problems = append(problems, fmt.Sprintf("%d trailing bytes not covered by any tensor", buf-pos))
	}
	if len(problems) > 5 {
		problems = append(problems[:5], fmt.Sprintf("and %d more", len(problems)-5))
	}
	dl := make([]string, 0, len(dtypes))
	for d := range dtypes {
		dl = append(dl, d)
	}
	sort.Strings(dl)
	return fmt.Sprintf("%d tensors (%s), header %d bytes", len(spans), strings.Join(dl, ","), n), problems
}

var npyDescr = regexp.MustCompile(`['"]descr['"]\s*:\s*(.*?)\s*,\s*['"]fortran_order`)

// checkNpy parses a .npy header; object arrays carry a pickle after it.
func checkNpy(r io.Reader, fa *facts, where string, maxPickle int64) (string, error) {
	br := bufio.NewReader(r)
	var h [8]byte
	if _, err := io.ReadFull(br, h[:]); err != nil || string(h[:6]) != "\x93NUMPY" {
		return "", fmt.Errorf("%sbad .npy magic", prefix(where))
	}
	var hl uint32
	switch h[6] {
	case 1:
		var b [2]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return "", fmt.Errorf("%struncated .npy header", prefix(where))
		}
		hl = uint32(binary.LittleEndian.Uint16(b[:]))
	case 2, 3:
		var b [4]byte
		if _, err := io.ReadFull(br, b[:]); err != nil {
			return "", fmt.Errorf("%struncated .npy header", prefix(where))
		}
		hl = binary.LittleEndian.Uint32(b[:])
	default:
		return "", fmt.Errorf("%sunsupported .npy version %d", prefix(where), h[6])
	}
	if hl > 1<<20 {
		return "", fmt.Errorf("%s.npy header too large", prefix(where))
	}
	hdr := make([]byte, hl)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return "", fmt.Errorf("%struncated .npy header", prefix(where))
	}
	m := npyDescr.FindSubmatch(hdr)
	if m == nil {
		return "", fmt.Errorf("%s.npy header has no descr", prefix(where))
	}
	descr := string(m[1])
	if strings.Contains(descr, "'O'") || strings.Contains(descr, "'|O'") || strings.Contains(descr, `"|O"`) || strings.Contains(descr, `"O"`) {
		fa.addScan(where, ScanPickle(br, false, maxPickle))
		return "numpy object array (pickled; np.load(allow_pickle=True) executes it)", nil
	}
	return "numpy array " + strings.Trim(descr, `'"`), nil
}

func prefix(where string) string {
	if where == "" {
		return ""
	}
	return where + ": "
}

var kerasLambda = regexp.MustCompile(`"class_name"\s*:\s*"Lambda"`)

// checkZip looks inside zip containers: torch (data.pkl and other .pkl
// entries), npz (.npy entries) and Keras v3 (config.json Lambda layers).
func checkZip(p string, size int64, fa *facts, maxPickle int64) {
	zr, err := zip.OpenReader(p)
	if err != nil {
		fa.malformed = append(fa.malformed, "unreadable zip: "+err.Error())
		if IsPickleName(p) {
			fa.pickle = true
		}
		return
	}
	defer zr.Close()
	if len(zr.File) > 100000 {
		fa.malformed = append(fa.malformed, fmt.Sprintf("zip with %d entries", len(zr.File)))
		return
	}
	var pkls, npys int
	torch := false
	for _, f := range zr.File {
		name := f.Name
		lower := strings.ToLower(name)
		switch {
		case strings.HasSuffix(lower, ".pkl"):
			pkls++
			if path.Base(lower) == "data.pkl" {
				torch = true
			}
			rc, err := f.Open()
			if err != nil {
				fa.pickle = true
				fa.partial = name + ": " + err.Error()
				continue
			}
			s := ScanPickle(rc, false, maxPickle)
			rc.Close()
			if s.Err == errNotPickle {
				s.Err = fmt.Errorf("not a pickle stream")
			}
			fa.addScan(name, s)
		case strings.HasSuffix(lower, ".npy"):
			npys++
			rc, err := f.Open()
			if err != nil {
				continue
			}
			if _, err := checkNpy(rc, fa, name, maxPickle); err != nil {
				fa.malformed = append(fa.malformed, err.Error())
			}
			rc.Close()
		case lower == "config.json" && strings.HasSuffix(strings.ToLower(p), ".keras"):
			rc, err := f.Open()
			if err != nil {
				continue
			}
			b, _ := io.ReadAll(io.LimitReader(rc, 16<<20))
			rc.Close()
			fa.lambda = kerasLambda.Match(b)
		}
	}
	switch {
	case torch:
		fa.format = FmtTorchZip
		fa.details = fmt.Sprintf("torch zip archive, %d pickle(s), %d entries", pkls, len(zr.File))
	case strings.HasSuffix(strings.ToLower(p), ".keras"):
		fa.format = FmtKeras
		fa.details = "Keras v3 archive"
	case npys > 0 && pkls == 0:
		fa.format = FmtNpz
		fa.details = fmt.Sprintf("npz archive, %d arrays", npys)
	default:
		fa.details = fmt.Sprintf("zip archive, %d entries, %d pickle(s)", len(zr.File), pkls)
	}
}
