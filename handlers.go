package main

import (
	"compress/gzip"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var nameRe = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func sanitizeName(s string) string {
	s = path.Base(strings.ReplaceAll(s, "\\", "/"))
	s = nameRe.ReplaceAllString(s, "_")
	s = strings.Trim(s, "._")
	if len(s) > 120 {
		s = s[len(s)-120:]
	}
	if s == "" {
		s = "file"
	}
	return s
}

// Formats that are already compressed; gzipping them again wastes CPU and
// usually grows the payload.
var compressedExts = map[string]bool{
	".gz": true, ".tgz": true, ".bz2": true, ".xz": true, ".zst": true,
	".lz4": true, ".br": true, ".zip": true, ".rar": true, ".7z": true,
	".jar": true, ".jpg": true, ".jpeg": true, ".png": true, ".gif": true,
	".webp": true, ".avif": true, ".heic": true, ".mp3": true, ".ogg": true,
	".flac": true, ".mp4": true, ".m4v": true, ".mov": true, ".webm": true,
	".dmg": true, ".apk": true,
}

func shouldCompress(name string) bool {
	return !compressedExts[strings.ToLower(filepath.Ext(name))]
}

func contentType(name string) string {
	if ct := mime.TypeByExtension(filepath.Ext(name)); ct != "" {
		return ct
	}
	return "application/octet-stream"
}

func acceptsGzip(r *http.Request) bool {
	for _, tok := range strings.Split(r.Header.Get("Accept-Encoding"), ",") {
		tok = strings.TrimSpace(strings.SplitN(tok, ";", 2)[0])
		if tok == "gzip" || tok == "*" {
			return true
		}
	}
	return false
}

func (s *server) clientIP(r *http.Request) string {
	if s.cfg.BehindProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			return strings.TrimSpace(strings.SplitN(xff, ",", 2)[0])
		}
	}
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ap.Addr().String()
}

func (s *server) uploadAllowed(ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, n := range s.cfg.AllowNets {
		if n.Contains(a) {
			return true
		}
	}
	return false
}

func (s *server) baseURL(r *http.Request) string {
	if s.cfg.BaseURL != "" {
		return s.cfg.BaseURL
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if s.cfg.BehindProxy {
		if p := r.Header.Get("X-Forwarded-Proto"); p != "" {
			scheme = strings.SplitN(p, ",", 2)[0]
		}
	}
	return scheme + "://" + r.Host
}

// uploadLimit returns the byte cap for this request; 0 means unlimited
// (requires a valid UNLOCK_KEY presented via ?key= or X-Upload-Key).
func (s *server) uploadLimit(r *http.Request) int64 {
	if s.cfg.UnlockKey != "" {
		k := r.URL.Query().Get("key")
		if k == "" {
			k = r.Header.Get("X-Upload-Key")
		}
		if k != "" && subtle.ConstantTimeCompare([]byte(k), []byte(s.cfg.UnlockKey)) == 1 {
			return 0
		}
	}
	return s.cfg.MaxUpload
}

func (s *server) index(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	keyHint := ""
	if s.cfg.UnlockKey != "" {
		keyHint = "\nappend ?key=<unlock-key> for unlimited."
	}
	fmt.Fprintf(w, `dumpd - dead simple file drops

upload (from an allowed IP):
  curl %[1]s -T file.tar.gz
  curl %[1]s -F file=@file.tar.gz
  curl %[1]s --data-binary @file.tar.gz

returns a download URL valid for %[2]s, rolling on every access.
max upload %[3]d MB.%[4]s
`, s.baseURL(r), s.cfg.TTL, s.cfg.MaxUpload>>20, keyHint)
}

func (s *server) healthz(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte("ok\n"))
}

func (s *server) upload(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if !s.uploadAllowed(ip) {
		http.Error(w, "upload not permitted from your IP\n", http.StatusForbidden)
		return
	}

	var name string
	var meta *Meta
	var err error
	limit := s.uploadLimit(r)

	ct := r.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "multipart/form-data") {
		name, meta, err = s.saveMultipart(w, r, limit)
	} else {
		name = sanitizeName(r.URL.Query().Get("filename"))
		if name == "file" {
			if p := sanitizeName(r.URL.Path); p != "file" {
				name = p
			}
		}
		var body io.Reader = r.Body
		if limit > 0 {
			body = http.MaxBytesReader(w, r.Body, limit)
		}
		meta, err = s.save(body, name, limit)
	}
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) || errors.Is(err, errTooLarge) {
			http.Error(w, "file too large\n", http.StatusRequestEntityTooLarge)
			return
		}
		logLine("upload ip=%s err=%v", ip, err)
		http.Error(w, "upload failed\n", http.StatusInternalServerError)
		return
	}
	if meta == nil {
		http.Error(w, "no file in request\n", http.StatusBadRequest)
		return
	}

	dl := s.baseURL(r) + "/d/" + meta.ID + "/" + url.PathEscape(meta.Filename)
	del := s.baseURL(r) + "/d/" + meta.ID + "?key=" + meta.DeleteKey
	w.Header().Set("X-Delete-Url", del)
	logLine("upload ip=%s id=%s name=%q size=%d stored=%d gzip=%v",
		ip, meta.ID, meta.Filename, meta.Size, meta.StoredSize, meta.Gzipped)

	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"url":        dl,
			"delete_url": del,
			"filename":   meta.Filename,
			"size":       meta.Size,
			"sha256":     meta.SHA256,
			"expires":    meta.Expires.UTC().Format(time.RFC3339),
		})
		return
	}
	fmt.Fprintln(w, dl)
}

var errTooLarge = errors.New("file too large")

func (s *server) saveMultipart(w http.ResponseWriter, r *http.Request, limit int64) (string, *Meta, error) {
	mr, err := r.MultipartReader()
	if err != nil {
		return "", nil, err
	}
	var name string
	var meta *Meta
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", nil, err
		}
		if meta == nil && p.FileName() != "" {
			name = sanitizeName(r.URL.Query().Get("filename"))
			if name == "file" {
				name = sanitizeName(p.FileName())
			}
			var src io.Reader = p
			if limit > 0 {
				src = io.LimitReader(p, limit+1)
			}
			meta, err = s.save(src, name, limit)
			if err != nil {
				return "", nil, err
			}
			continue
		}
		io.Copy(io.Discard, p) // drain any extra parts
	}
	return name, meta, nil
}

// save streams src to disk, gzip-compressing at rest when worthwhile.
// limit <= 0 means unlimited.
func (s *server) save(src io.Reader, name string, limit int64) (*Meta, error) {
	id := newToken(8)
	if _, err := s.store.loadMeta(id); err == nil {
		id = newToken(8) // one retry on the astronomically unlikely collision
	}

	tmp, err := os.CreateTemp(s.store.tmpDir, "up-*")
	if err != nil {
		return nil, err
	}
	tmpName := tmp.Name()
	cleanup := func(e error) error {
		tmp.Close()
		os.Remove(tmpName)
		return e
	}

	gz := shouldCompress(name)
	h := sha256.New()
	var n int64
	if gz {
		gzw := gzip.NewWriter(tmp)
		n, err = io.Copy(io.MultiWriter(gzw, h), src)
		if cerr := gzw.Close(); err == nil {
			err = cerr
		}
	} else {
		n, err = io.Copy(io.MultiWriter(tmp, h), src)
	}
	if err != nil {
		return nil, cleanup(err)
	}
	if limit > 0 && n > limit {
		return nil, cleanup(errTooLarge)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return nil, err
	}
	if err := os.Rename(tmpName, s.store.blobPath(id)); err != nil {
		os.Remove(tmpName)
		return nil, err
	}
	st, _ := os.Stat(s.store.blobPath(id))
	m := &Meta{
		ID:        id,
		Filename:  name,
		Size:      n,
		SHA256:    hex.EncodeToString(h.Sum(nil)),
		Gzipped:   gz,
		Created:   time.Now(),
		Expires:   time.Now().Add(s.cfg.TTL),
		DeleteKey: newToken(24),
	}
	if st != nil {
		m.StoredSize = st.Size()
	}
	if err := s.store.writeMeta(m); err != nil {
		s.store.delete(id)
		return nil, err
	}
	return m, nil
}

func (s *server) download(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	m, err := s.store.loadMeta(id)
	if err != nil {
		http.Error(w, "not found\n", http.StatusNotFound)
		return
	}
	f, err := os.Open(s.store.blobPath(id))
	if err != nil {
		http.Error(w, "not found\n", http.StatusNotFound)
		return
	}
	defer f.Close()

	s.store.touch(m, s.cfg.TTL) // every access rolls the expiry forward

	w.Header().Set("Content-Type", contentType(m.Filename))
	w.Header().Set("Content-Disposition", `attachment; filename="`+m.Filename+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, max-age=86400")
	if m.Gzipped {
		w.Header().Set("Vary", "Accept-Encoding")
	}

	switch {
	case m.Gzipped && acceptsGzip(r):
		// Serve the stored gzip stream straight off disk.
		w.Header().Set("Content-Encoding", "gzip")
		http.ServeContent(w, r, "", m.Created, f)
	case m.Gzipped:
		gzr, err := gzip.NewReader(f)
		if err != nil {
			http.Error(w, "corrupt file\n", http.StatusInternalServerError)
			return
		}
		defer gzr.Close()
		w.Header().Set("Content-Length", strconv.FormatInt(m.Size, 10))
		w.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			io.Copy(w, gzr)
		}
	default:
		http.ServeContent(w, r, "", m.Created, f)
	}
}

func (s *server) del(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	m, err := s.store.loadMeta(id)
	if err != nil {
		http.Error(w, "not found\n", http.StatusNotFound)
		return
	}
	key := r.URL.Query().Get("key")
	if key == "" {
		key = r.Header.Get("X-Delete-Key")
	}
	if key == "" || subtle.ConstantTimeCompare([]byte(key), []byte(m.DeleteKey)) != 1 {
		http.Error(w, "forbidden\n", http.StatusForbidden)
		return
	}
	s.store.delete(id)
	logLine("delete id=%s ip=%s", id, s.clientIP(r))
	fmt.Fprintln(w, "deleted")
}
