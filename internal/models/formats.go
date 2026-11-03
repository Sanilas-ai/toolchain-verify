package models

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// Formats reported for artifacts.
const (
	FmtGGUF        = "gguf"
	FmtSafetensors = "safetensors"
	FmtPickle      = "pickle"
	FmtTorchZip    = "torch-zip"
	FmtZip         = "zip"
	FmtNpy         = "npy"
	FmtNpz         = "npz"
	FmtKeras       = "keras"
	FmtHDF5        = "hdf5"
	FmtGzip        = "gzip"
	FmtZlib        = "zlib"
	FmtBzip2       = "bzip2"
	FmtXZ          = "xz"
	FmtLZ4         = "lz4"
	FmtText        = "text"
	FmtUnknown     = "unknown"
)

// artifactExts are the file name suffixes collected under scan roots.
var artifactExts = []string{
	".gguf", ".safetensors", ".bin", ".pt", ".pth", ".ckpt", ".pkl", ".pickle", ".joblib", ".jbl",
	".npy", ".npz", ".h5", ".hdf5", ".keras", ".onnx", ".pdparams", ".pdopt", ".pdiparams.info",
}

// pickleExts are suffixes whose files are commonly pickles (or zip
// archives with pickles inside) and are deserialized with pickle.
var pickleExts = []string{".pkl", ".pickle", ".joblib", ".jbl", ".pt", ".pth", ".ckpt", ".bin", ".pdparams", ".pdopt", ".pdiparams.info", ".npy", ".npz"}

func hasSuffixAny(name string, exts []string) bool {
	n := strings.ToLower(name)
	for _, e := range exts {
		if strings.HasSuffix(n, e) {
			return true
		}
	}
	return false
}

// IsArtifactName reports whether a file name looks like a model artifact.
func IsArtifactName(name string) bool {
	if strings.HasPrefix(filepath.Base(name), "._") { // macOS AppleDouble
		return false
	}
	return hasSuffixAny(name, artifactExts)
}

// IsPickleName reports whether a file name is commonly a pickle container.
func IsPickleName(name string) bool { return hasSuffixAny(name, pickleExts) }

// SniffHeader classifies a file from its first bytes and size.
func SniffHeader(b []byte, size int64) string {
	switch {
	case len(b) >= 4 && string(b[:4]) == "GGUF":
		return FmtGGUF
	case len(b) >= 4 && (string(b[:4]) == "PK\x03\x04" || string(b[:4]) == "PK\x05\x06"):
		return FmtZip
	case len(b) >= 6 && string(b[:6]) == "\x93NUMPY":
		return FmtNpy
	case len(b) >= 8 && string(b[:8]) == "\x89HDF\r\n\x1a\n":
		return FmtHDF5
	case len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b:
		return FmtGzip
	case len(b) >= 3 && string(b[:3]) == "BZh":
		return FmtBzip2
	case len(b) >= 6 && string(b[:6]) == "\xfd7zXZ\x00":
		return FmtXZ
	case len(b) >= 4 && string(b[:4]) == "\x04\x22\x4d\x18":
		return FmtLZ4
	case len(b) >= 2 && b[0] == 0x80 && b[1] >= 1 && b[1] <= 5:
		return FmtPickle
	case len(b) >= 2 && b[0] == 0x78 && (b[1] == 0x01 || b[1] == 0x5e || b[1] == 0x9c || b[1] == 0xda):
		return FmtZlib
	}
	if len(b) >= 10 {
		n := binary.LittleEndian.Uint64(b[:8])
		if b[8] == '{' && n >= 2 && n < 1<<30 && int64(n)+8 <= size {
			return FmtSafetensors
		}
	}
	if looksText(b) {
		return FmtText
	}
	return FmtUnknown
}

func looksText(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if !utf8.Valid(trimPartialRune(b)) {
		return false
	}
	return !bytes.ContainsAny(b, "\x00\x01\x02\x03\x04\x05\x06\x07\x08\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f")
}

func trimPartialRune(b []byte) []byte {
	for i := 0; i < 3 && len(b) > 0; i++ {
		if utf8.Valid(b) {
			return b
		}
		b = b[:len(b)-1]
	}
	return b
}

// Sniff classifies a file by its first bytes (no parsing). Zip archives
// whose names are typical torch extensions are reported as torch-zip.
func Sniff(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return "", err
	}
	b := make([]byte, 512)
	n, _ := io.ReadFull(f, b)
	fm := SniffHeader(b[:n], st.Size())
	if fm == FmtZip && hasSuffixAny(path, []string{".pt", ".pth", ".ckpt", ".bin"}) {
		fm = FmtTorchZip
	}
	return fm, nil
}

// PickleLike reports whether a sniffed format is (or usually wraps) a
// pickle stream for a file with the given name.
func PickleLike(format, name string) bool {
	switch format {
	case FmtPickle, FmtTorchZip:
		return true
	case FmtZip, FmtGzip, FmtZlib, FmtBzip2, FmtXZ, FmtLZ4:
		return IsPickleName(name)
	}
	return false
}
