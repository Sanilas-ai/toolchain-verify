package models

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Ollama stores models as content-addressed blobs (blobs/sha256-<hex>)
// referenced by OCI-style manifests (manifests/<registry>/<ns>/<model>/<tag>;
// newer releases add manifests-v2/ with symlinks to manifest blobs and
// manifest lists). Only those directories are read; the store's parent
// (which holds the instance's id_ed25519 key) is only stat-ed.

// OllamaReport summarizes the Ollama API and model stores.
type OllamaReport struct {
	URL       string        `json:"url,omitempty"`
	Version   string        `json:"version,omitempty"`
	APIError  string        `json:"api_error,omitempty"`
	APIModels []APIModel    `json:"api_models,omitempty"`
	Stores    []OllamaStore `json:"stores,omitempty"`
}

// APIModel is one entry of GET /api/tags.
type APIModel struct {
	Name    string `json:"name"`
	Digest  string `json:"digest"`
	Size    int64  `json:"size"`
	Format  string `json:"format,omitempty"`
	InStore string `json:"in_store,omitempty"`
}

// OllamaStore is one models directory.
type OllamaStore struct {
	Dir         string        `json:"dir"`
	Models      []OllamaModel `json:"models"`
	Blobs       int           `json:"blobs"`
	BlobBytes   int64         `json:"blob_bytes"`
	Orphans     []string      `json:"orphans,omitempty"`
	OrphanBytes int64         `json:"orphan_bytes,omitempty"`
	Partial     []string      `json:"partial,omitempty"`
}

// OllamaModel is one manifest.
type OllamaModel struct {
	Name     string        `json:"name"`
	Registry string        `json:"registry"`
	Manifest string        `json:"manifest"`
	Layers   []OllamaLayer `json:"layers"`
}

// OllamaLayer is one manifest layer.
type OllamaLayer struct {
	Type   string `json:"type"` // media type without the vnd.ollama.image. prefix
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
	From   string `json:"from,omitempty"`
}

type manifestDoc struct {
	MediaType string `json:"mediaType"`
	Config    *struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	} `json:"config"`
	Layers []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
		From      string `json:"from"`
	} `json:"layers"`
	Manifests []struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Runner    string `json:"runner"`
		Format    string `json:"format"`
	} `json:"manifests"`
}

// blobRef is a reference from a manifest to a blob.
type blobRef struct {
	digest  string // hex
	size    int64  // -1 when unknown
	kind    string // layer type, "config", "manifest", "variant"
	model   string
	variant string // runner/format of a manifest-list child
}

func digestHex(d string) string {
	h := strings.TrimPrefix(strings.TrimPrefix(d, "sha256:"), "sha256-")
	if !hexRe.MatchString(h) {
		return ""
	}
	return h
}

func blobPath(store, hex string) string { return filepath.Join(store, "blobs", "sha256-"+hex) }

// modelName turns manifests/<registry>/<ns>/<model>/<tag> into the name
// Ollama shows.
func modelName(rel string, first []string) (name, registry string) {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	if len(parts) < 4 {
		return strings.Join(parts, "/"), ""
	}
	reg, ns, model, tag := parts[0], strings.Join(parts[1:len(parts)-2], "/"), parts[len(parts)-2], parts[len(parts)-1]
	official := false
	for _, r := range first {
		if reg == r {
			official = true
		}
	}
	switch {
	case official && ns == "library":
		name = model
	case official:
		name = ns + "/" + model
	default:
		name = reg + "/" + ns + "/" + model
	}
	if tag != "" {
		name += ":" + tag
	}
	return name, reg
}

type storeScan struct {
	store  OllamaStore
	refs   []blobRef
	blobs  map[string]os.FileInfo // hex -> info
	issues []issue
}

type issue struct {
	rule, sev, path, msg, fix string
}

// scanStore reads manifests and lists blobs of one Ollama store.
func scanStore(dir string, registries []string) *storeScan {
	s := &storeScan{store: OllamaStore{Dir: dir}, blobs: map[string]os.FileInfo{}}
	ents, err := os.ReadDir(filepath.Join(dir, "blobs"))
	if err != nil {
		s.issues = append(s.issues, issue{"ollama.store-unreadable", "warn", dir, "cannot list blobs: " + errText(err), "run as a user that can read the store (read-only)"})
		return s
	}
	for _, e := range ents {
		n := e.Name()
		if strings.Contains(n, "-partial") {
			s.store.Partial = append(s.store.Partial, n)
			continue
		}
		hex := digestHex(n)
		if hex == "" {
			continue
		}
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		s.blobs[hex] = info
		s.store.Blobs++
		s.store.BlobBytes += info.Size()
	}
	if st, err := os.Stat(filepath.Join(dir, "blobs")); err == nil && st.Mode().Perm()&0o002 != 0 {
		s.issues = append(s.issues, issue{"ollama.writable", "fail", filepath.Join(dir, "blobs"), "blob directory is world-writable: any local user can swap model weights", "chmod o-w"})
	}
	models := map[string]*OllamaModel{}
	var order []string
	seenRef := map[string]bool{}
	addRef := func(r blobRef) {
		k := r.model + "\x00" + r.digest + "\x00" + r.kind
		if !seenRef[k] {
			seenRef[k] = true
			s.refs = append(s.refs, r)
		}
	}
	var parse func(m *OllamaModel, data []byte, mpath string, depth int)
	parse = func(m *OllamaModel, data []byte, mpath string, depth int) {
		var doc manifestDoc
		if err := json.Unmarshal(data, &doc); err != nil {
			s.issues = append(s.issues, issue{"ollama.manifest-invalid", "warn", mpath, "manifest is not valid JSON: " + errText(err), ""})
			return
		}
		if doc.Config != nil {
			if h := digestHex(doc.Config.Digest); h != "" {
				addRef(blobRef{h, doc.Config.Size, "config", m.Name, ""})
			}
		}
		for _, l := range doc.Layers {
			h := digestHex(l.Digest)
			if h == "" {
				s.issues = append(s.issues, issue{"ollama.manifest-invalid", "warn", mpath, fmt.Sprintf("layer digest %q is not sha256", l.Digest), ""})
				continue
			}
			typ := strings.TrimPrefix(l.MediaType, "application/vnd.ollama.image.")
			if strings.Contains(l.MediaType, "manifest") {
				typ = "manifest"
			}
			addRef(blobRef{h, l.Size, typ, m.Name, ""})
			if typ != "manifest" && typ != "config" {
				dup := false
				for _, x := range m.Layers {
					if x.Digest == h {
						dup = true
					}
				}
				if !dup {
					m.Layers = append(m.Layers, OllamaLayer{typ, h, l.Size, l.From})
				}
			}
		}
		for _, c := range doc.Manifests {
			h := digestHex(c.Digest)
			if h == "" {
				continue
			}
			v := strings.Trim(c.Runner+"/"+c.Format, "/")
			addRef(blobRef{h, -1, "variant", m.Name, v})
			if depth > 0 {
				continue
			}
			if _, ok := s.blobs[h]; !ok {
				continue // variant not pulled
			}
			if b, err := readSmall(blobPath(dir, h)); err == nil {
				parse(m, b, blobPath(dir, h), depth+1)
			}
		}
	}
	for _, sub := range []string{"manifests", "manifests-v2"} {
		root := filepath.Join(dir, sub)
		_ = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p == root && errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				s.issues = append(s.issues, issue{"ollama.store-unreadable", "warn", p, errText(err), ""})
				return nil
			}
			if d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(root, p)
			target := p
			if d.Type()&fs.ModeSymlink != 0 {
				t, err := filepath.EvalSymlinks(p)
				if err != nil {
					s.issues = append(s.issues, issue{"ollama.manifest-invalid", "warn", p, "dangling manifest symlink", ""})
					return nil
				}
				bd, _ := filepath.EvalSymlinks(filepath.Join(dir, "blobs"))
				if bd == "" || !strings.HasPrefix(t, bd+string(filepath.Separator)) {
					s.issues = append(s.issues, issue{"ollama.manifest-escape", "fail", p, "manifest symlink points outside the blob store: " + t, "remove it and re-pull the model"})
					return nil
				}
				target = t
				if h := digestHex(filepath.Base(t)); h != "" {
					addRef(blobRef{h, -1, "manifest", "", ""})
				}
			} else if !d.Type().IsRegular() {
				return nil
			}
			data, err := readSmall(target)
			if err != nil {
				s.issues = append(s.issues, issue{"ollama.store-unreadable", "warn", p, errText(err), ""})
				return nil
			}
			name, reg := modelName(rel, registries)
			m, ok := models[name]
			if !ok {
				m = &OllamaModel{Name: name, Registry: reg, Manifest: p}
				models[name] = m
				order = append(order, name)
				for i := range s.refs { // fix up the symlink ref model name
					if s.refs[i].model == "" {
						s.refs[i].model = name
					}
				}
			}
			parse(m, data, p, 0)
			return nil
		})
	}
	sort.Strings(order)
	for _, n := range order {
		s.store.Models = append(s.store.Models, *models[n])
	}
	return s
}

func readSmall(p string) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 4<<20))
}

func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// queryAPI reads /api/version and /api/tags. It sends no credentials,
// follows no redirects and caps the response size.
func queryAPI(base string, timeout time.Duration) (string, []APIModel, error) {
	c := &http.Client{
		Timeout:       timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport:     &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: timeout}).DialContext},
	}
	get := func(path string, v any) error {
		resp, err := c.Get(base + path)
		if err != nil {
			var ue *url.Error
			if errors.As(err, &ue) {
				return ue.Err
			}
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			return fmt.Errorf("GET %s: HTTP %d", path, resp.StatusCode)
		}
		return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(v)
	}
	var ver struct {
		Version string `json:"version"`
	}
	if err := get("/api/version", &ver); err != nil {
		return "", nil, err
	}
	var tags struct {
		Models []struct {
			Name    string `json:"name"`
			Digest  string `json:"digest"`
			Size    int64  `json:"size"`
			Details struct {
				Format string `json:"format"`
			} `json:"details"`
		} `json:"models"`
	}
	if err := get("/api/tags", &tags); err != nil {
		return ver.Version, nil, err
	}
	out := make([]APIModel, 0, len(tags.Models))
	for _, m := range tags.Models {
		out = append(out, APIModel{Name: m.Name, Digest: digestHex(m.Digest), Size: m.Size, Format: m.Details.Format})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return ver.Version, out, nil
}

func isLoopbackURL(u string) bool {
	pu, err := url.Parse(u)
	if err != nil {
		return false
	}
	h := pu.Hostname()
	if h == "localhost" {
		return true
	}
	ip := net.ParseIP(h)
	return ip != nil && ip.IsLoopback()
}
