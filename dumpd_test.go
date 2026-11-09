package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testServer(t *testing.T) *server {
	t.Helper()
	st, err := newStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return &server{
		cfg: &Config{
			DataDir:      st.dir,
			TTL:          time.Hour,
			MaxUpload:    1 << 20,
			SweepEvery:   time.Minute,
			TLSAddr:      ":443",
			MinFreeBytes: 0,
		},
		store: st,
	}
}

func allowLocal(s *server) {
	p := netip.MustParseAddr("192.0.2.1")
	s.cfg.AllowNets = []netip.Prefix{netip.PrefixFrom(p, 32)}
}

func putUpload(t *testing.T, s *server, target, body, ctype string) *httptest.ResponseRecorder {
	t.Helper()
	var rdr io.Reader = strings.NewReader(body)
	req := httptest.NewRequest(http.MethodPut, target, rdr)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	rec := httptest.NewRecorder()
	s.upload(rec, req)
	return rec
}

// downloadID extracts the file id from a "/d/<id>/..." download URL.
func downloadID(dl string) string {
	rest := strings.SplitN(dl, "/d/", 2)[1]
	return strings.SplitN(rest, "/", 2)[0]
}

func getDownload(t *testing.T, s *server, dl string, hdr map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, dl, nil)
	req.SetPathValue("id", downloadID(dl))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.download(rec, req)
	return rec
}

// ---------- pure helpers ----------

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"backup.tar.gz":          "backup.tar.gz",
		"../../etc/passwd":       "passwd",
		`C:\Users\x\file.txt`:    "file.txt",
		"a b/c*d?.txt":           "c_d_.txt",
		"..":                     "file",
		"":                       "file",
		".hidden":                "hidden",
		"name with\ttab.txt":     "name_with_tab.txt",
		strings.Repeat("x", 200): strings.Repeat("x", 120),
	}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestAcceptsGzip(t *testing.T) {
	cases := []struct {
		header string
		want   bool
	}{
		{"", false},
		{"gzip", true},
		{"GZip", true},
		{"identity", false},
		{"br, gzip", true},
		{"*", true},
		{"gzip;q=0", false},
		{"gzip;q=0.0", false},
		{"gzip;q=0.5", true},
		{"br;q=1, gzip;q=0", false},
		{"*;q=0", false},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if c.header != "" {
			req.Header.Set("Accept-Encoding", c.header)
		}
		if got := acceptsGzip(req); got != c.want {
			t.Errorf("acceptsGzip(%q) = %v, want %v", c.header, got, c.want)
		}
	}
}

func TestAcceptsJSON(t *testing.T) {
	cases := []struct {
		accept string
		want   bool
	}{
		{"", false},
		{"*/*", false},
		{"application/json", true},
		{"text/html, application/json;q=0.9", true},
		{"Application/JSON", true},
		{"application/json;q=0", false},
		{"application/json; charset=utf-8", true},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if c.accept != "" {
			req.Header.Set("Accept", c.accept)
		}
		if got := acceptsJSON(req); got != c.want {
			t.Errorf("acceptsJSON(%q) = %v, want %v", c.accept, got, c.want)
		}
	}
}

func TestConstTimeEq(t *testing.T) {
	if !constTimeEq("s3cret", "s3cret") {
		t.Error("equal strings should match")
	}
	if constTimeEq("s3cret", "s3creX") {
		t.Error("different strings should not match")
	}
	if constTimeEq("short", "a-much-longer-secret-value") {
		t.Error("different lengths should not match")
	}
}

func TestETagMatches(t *testing.T) {
	sha := "abc123"
	cases := []struct {
		header string
		want   bool
	}{
		{"", false},
		{`W/"abc123"`, true},
		{`"abc123"`, true},
		{`abc123`, true},
		{"*", true},
		{`W/"abc123", "def456"`, true},
		{`"def456"`, false},
		{`W/"def456"`, false},
	}
	for _, c := range cases {
		if got := etagMatches(c.header, sha); got != c.want {
			t.Errorf("etagMatches(%q) = %v, want %v", c.header, got, c.want)
		}
	}
}

func TestShouldCompress(t *testing.T) {
	for name, want := range map[string]bool{
		"a.txt": true, "a.tar.gz": false, "A.PNG": false, "noext": true,
	} {
		if got := shouldCompress(name); got != want {
			t.Errorf("shouldCompress(%q) = %v, want %v", name, got, want)
		}
	}
}

// ---------- clientIP / allowlist ----------

func proxyServer(t *testing.T, hops int, nets ...string) *server {
	t.Helper()
	s := testServer(t)
	s.cfg.BehindProxy = true
	s.cfg.ProxyHops = hops
	for _, n := range nets {
		s.cfg.AllowNets = append(s.cfg.AllowNets, netip.MustParsePrefix(n))
	}
	return s
}

func TestClientIPXFF(t *testing.T) {
	s := proxyServer(t, 1, "9.9.9.9/32")

	// proxy appended the real client; a spoofed leftmost entry must lose
	req := httptest.NewRequest(http.MethodPut, "/", nil)
	req.RemoteAddr = "10.0.0.1:1234"
	req.Header.Set("X-Forwarded-For", "1.2.3.4, 9.9.9.9")
	if got := s.clientIP(req); got != "9.9.9.9" {
		t.Fatalf("clientIP = %q, want 9.9.9.9", got)
	}
	if !s.uploadAllowed(s.clientIP(req)) {
		t.Fatal("allowlisted rightmost IP should be permitted")
	}

	// two trusted proxies: the client sits two entries from the right
	s2 := proxyServer(t, 2, "8.8.8.8/32")
	req2 := httptest.NewRequest(http.MethodPut, "/", nil)
	req2.RemoteAddr = "10.0.0.1:1234"
	req2.Header.Set("X-Forwarded-For", "8.8.8.8, 7.7.7.7")
	if got := s2.clientIP(req2); got != "8.8.8.8" {
		t.Fatalf("clientIP hops=2 = %q, want 8.8.8.8", got)
	}

	// fewer entries than hops -> clamp to leftmost
	req3 := httptest.NewRequest(http.MethodPut, "/", nil)
	req3.RemoteAddr = "10.0.0.1:1234"
	req3.Header.Set("X-Forwarded-For", "5.5.5.5")
	if got := s2.clientIP(req3); got != "5.5.5.5" {
		t.Fatalf("clientIP clamp = %q, want 5.5.5.5", got)
	}
}

func TestClientIPNoProxy(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodPut, "/", nil)
	req.RemoteAddr = "192.0.2.10:5555"
	req.Header.Set("X-Forwarded-For", "1.2.3.4") // must be ignored
	if got := s.clientIP(req); got != "192.0.2.10" {
		t.Fatalf("clientIP = %q, want 192.0.2.10", got)
	}
}

func TestClientIPv6Unmap(t *testing.T) {
	s := testServer(t)
	s.cfg.AllowNets = []netip.Prefix{netip.MustParsePrefix("1.2.3.4/32")}
	req := httptest.NewRequest(http.MethodPut, "/", nil)
	req.RemoteAddr = "[::ffff:1.2.3.4]:5555"
	if got := s.clientIP(req); got != "1.2.3.4" {
		t.Fatalf("clientIP = %q, want 1.2.3.4", got)
	}
	if !s.uploadAllowed(s.clientIP(req)) {
		t.Fatal("IPv4-mapped IPv6 should match IPv4 allowlist entry")
	}
}

// ---------- upload / download round trip ----------

func TestUploadDownloadRoundTrip(t *testing.T) {
	s := testServer(t)
	allowLocal(s)

	payload := strings.Repeat("hello dumpd ", 100)
	rec := putUpload(t, s, "http://x/backup.tar.gz?filename=backup.tar.gz", payload, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d, body=%s", rec.Code, rec.Body.String())
	}
	dl := strings.TrimSpace(rec.Body.String())
	if !strings.Contains(dl, "/d/") {
		t.Fatalf("unexpected upload response %q", dl)
	}
	if !strings.HasSuffix(dl, "/backup.tar.gz") {
		t.Fatalf("download URL missing filename: %q", dl)
	}

	// plain download (curl sends no Accept-Encoding) -> identity bytes
	rec = getDownload(t, s, dl, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("download status = %d", rec.Code)
	}
	if rec.Body.String() != payload {
		t.Fatalf("downloaded body mismatch: got %d bytes", rec.Body.Len())
	}
	if ct := rec.Header().Get("Content-Disposition"); !strings.Contains(ct, "backup.tar.gz") {
		t.Fatalf("bad content-disposition %q", ct)
	}
	if et := rec.Header().Get("ETag"); !strings.HasPrefix(et, `W/"`) {
		t.Fatalf("missing weak ETag, got %q", et)
	}
	if csp := rec.Header().Get("Content-Security-Policy"); csp != "sandbox" {
		t.Fatalf("missing CSP sandbox, got %q", csp)
	}
}

func TestUploadGzipStoredAndServed(t *testing.T) {
	s := testServer(t)
	allowLocal(s)

	payload := strings.Repeat("compressible ", 500)
	rec := putUpload(t, s, "http://x/notes.txt?filename=notes.txt", payload, "")
	if rec.Code != http.StatusOK {
		t.Fatalf("upload status = %d", rec.Code)
	}
	dl := strings.TrimSpace(rec.Body.String())

	// gzip-capable client gets the stored gzip stream
	rec = getDownload(t, s, dl, map[string]string{"Accept-Encoding": "gzip"})
	if rec.Code != http.StatusOK {
		t.Fatalf("download status = %d", rec.Code)
	}
	if rec.Header().Get("Content-Encoding") != "gzip" {
		t.Fatal("expected Content-Encoding: gzip")
	}
	gzr, err := gzip.NewReader(rec.Body)
	if err != nil {
		t.Fatalf("response is not gzip: %v", err)
	}
	out, _ := io.ReadAll(gzr)
	if string(out) != payload {
		t.Fatal("gzip round trip mismatch")
	}

	// non-gzip client gets transparent decompression
	rec2 := getDownload(t, s, dl, nil)
	if rec2.Body.String() != payload {
		t.Fatal("transparent decompress mismatch")
	}
}

func TestUploadForbiddenAndTooLarge(t *testing.T) {
	s := testServer(t)
	// no allowlist entries -> denied
	rec := putUpload(t, s, "http://x/f.txt", "data", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", rec.Code)
	}

	allowLocal(s)
	s.cfg.MaxUpload = 4
	rec = putUpload(t, s, "http://x/f.txt", "more than four bytes", "")
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", rec.Code)
	}
}

func TestUploadJSONResponse(t *testing.T) {
	s := testServer(t)
	allowLocal(s)
	req := httptest.NewRequest(http.MethodPut, "http://x/f.bin?filename=f.bin", strings.NewReader("data"))
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	s.upload(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	for _, k := range []string{"url", "delete_url", "sha256", "expires"} {
		if resp[k] == nil {
			t.Fatalf("missing key %q in %v", k, resp)
		}
	}
}

func TestUploadMultipart(t *testing.T) {
	s := testServer(t)
	allowLocal(s)

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "report.csv")
	fw.Write([]byte("a,b,c\n1,2,3\n"))
	mw.WriteField("note", "extra field")
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "http://x/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	s.upload(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.HasSuffix(strings.TrimSpace(rec.Body.String()), "/report.csv") {
		t.Fatalf("unexpected url %q", rec.Body.String())
	}
}

func TestUploadMultipartMalformed(t *testing.T) {
	s := testServer(t)
	allowLocal(s)
	req := httptest.NewRequest(http.MethodPost, "http://x/upload", strings.NewReader("not multipart"))
	req.Header.Set("Content-Type", "multipart/form-data; boundary=zzz")
	rec := httptest.NewRecorder()
	s.upload(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestUploadMultipartTooLarge(t *testing.T) {
	s := testServer(t)
	allowLocal(s)
	s.cfg.MaxUpload = 8

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, _ := mw.CreateFormFile("file", "big.bin")
	fw.Write(bytes.Repeat([]byte("x"), 100))
	mw.Close()

	req := httptest.NewRequest(http.MethodPost, "http://x/upload", &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	s.upload(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (body=%s)", rec.Code, rec.Body.String())
	}
}

func TestDownloadMetadataJSON(t *testing.T) {
	s := testServer(t)
	allowLocal(s)

	rec := putUpload(t, s, "http://x/meta.txt?filename=meta.txt", "payload", "")
	dl := strings.TrimSpace(rec.Body.String())

	rec = getDownload(t, s, dl, map[string]string{"Accept": "application/json"})
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("content-type = %q", ct)
	}
	var meta map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &meta); err != nil {
		t.Fatal(err)
	}
	if meta["filename"] != "meta.txt" || meta["size"].(float64) != 7 {
		t.Fatalf("bad metadata: %v", meta)
	}
	if _, ok := meta["delete_key"]; ok {
		t.Fatal("metadata must not leak delete_key")
	}
}

func TestDownloadNotFound(t *testing.T) {
	s := testServer(t)
	req := httptest.NewRequest(http.MethodGet, "http://x/d/AAAAAAAAAAA/x", nil)
	req.SetPathValue("id", "AAAAAAAAAAA")
	rec := httptest.NewRecorder()
	s.download(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestDownloadConditional(t *testing.T) {
	s := testServer(t)
	allowLocal(s)
	rec := putUpload(t, s, "http://x/c.txt?filename=c.txt", "data", "")
	dl := strings.TrimSpace(rec.Body.String())

	rec = getDownload(t, s, dl, nil)
	etag := rec.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no etag on first download")
	}

	rec2 := getDownload(t, s, dl, map[string]string{"If-None-Match": etag})
	if rec2.Code != http.StatusNotModified {
		t.Fatalf("status = %d, want 304", rec2.Code)
	}
}

func TestDeleteFlow(t *testing.T) {
	s := testServer(t)
	allowLocal(s)

	req := httptest.NewRequest(http.MethodPut, "http://x/f.txt?filename=f.txt", strings.NewReader("data"))
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	s.upload(rec, req)
	var up map[string]any
	json.Unmarshal(rec.Body.Bytes(), &up)
	delURL := up["delete_url"].(string)
	id := downloadID(up["url"].(string))

	// wrong key -> 403
	dreq := httptest.NewRequest(http.MethodDelete, "http://x/d/"+id+"?key=wrong", nil)
	dreq.SetPathValue("id", id)
	drec := httptest.NewRecorder()
	s.del(drec, dreq)
	if drec.Code != http.StatusForbidden {
		t.Fatalf("wrong key status = %d", drec.Code)
	}

	// right key -> deleted
	dreq2 := httptest.NewRequest(http.MethodDelete, delURL, nil)
	dreq2.SetPathValue("id", id)
	drec2 := httptest.NewRecorder()
	s.del(drec2, dreq2)
	if drec2.Code != http.StatusOK {
		t.Fatalf("delete status = %d body=%s", drec2.Code, drec2.Body.String())
	}
}

// ---------- store / sweep ----------

func TestSweepExpiryAndOrphans(t *testing.T) {
	s := testServer(t)
	allowLocal(s)

	rec := putUpload(t, s, "http://x/live.txt?filename=live.txt", "x", "")
	liveURL := strings.TrimSpace(rec.Body.String())
	rec = putUpload(t, s, "http://x/dead.txt?filename=dead.txt", "x", "")
	deadURL := strings.TrimSpace(rec.Body.String())

	liveID := downloadID(liveURL)
	deadID := downloadID(deadURL)

	// expire the dead one
	m, err := s.store.loadMeta(deadID)
	if err != nil {
		t.Fatal(err)
	}
	m.Expires = time.Now().Add(-time.Hour)
	if err := s.store.writeMeta(m); err != nil {
		t.Fatal(err)
	}

	// an orphan blob older than grace
	orphan := filepath.Join(s.store.blobDir, "Orphan123456")
	os.WriteFile(orphan, []byte("x"), 0o600)
	old := time.Now().Add(-time.Hour)
	os.Chtimes(orphan, old, old)

	// a stale tmp file (older than the 24h tmpMaxAge)
	tmpf := filepath.Join(s.store.tmpDir, "up-stale")
	os.WriteFile(tmpf, []byte("x"), 0o600)
	ancient := time.Now().Add(-48 * time.Hour)
	os.Chtimes(tmpf, ancient, ancient)

	// a fresh tmp file must survive
	freshTmp := filepath.Join(s.store.tmpDir, "up-fresh")
	os.WriteFile(freshTmp, []byte("x"), 0o600)

	if n := s.store.sweep(time.Now()); n < 3 {
		t.Fatalf("sweep removed %d items, want >=3", n)
	}

	for _, p := range []string{s.store.blobPath(deadID), s.store.metaPath(deadID), orphan, tmpf} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("expected %s removed", p)
		}
	}
	for _, p := range []string{s.store.blobPath(liveID), s.store.metaPath(liveID), freshTmp} {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("expected %s to survive: %v", p, err)
		}
	}
}

func TestSweepRemovesCorruptMeta(t *testing.T) {
	s := testServer(t)
	badID := "BadMeta1234"
	os.WriteFile(s.store.metaPath(badID), []byte("{not json"), 0o600)
	os.WriteFile(s.store.blobPath(badID), []byte("x"), 0o600)

	s.store.sweep(time.Now())
	if _, err := os.Stat(s.store.metaPath(badID)); !os.IsNotExist(err) {
		t.Error("corrupt meta should be removed")
	}
	if _, err := os.Stat(s.store.blobPath(badID)); !os.IsNotExist(err) {
		t.Error("blob of corrupt meta should be removed")
	}
}

func TestSweepSkipsTransientMetaError(t *testing.T) {
	s := testServer(t)
	// a meta symlink pointing at itself makes ReadFile fail with ELOOP -
	// neither IsNotExist nor corrupt, so the sweeper must keep it.
	id := "LoopMeta123"
	os.Symlink(s.store.metaPath(id), s.store.metaPath(id))
	s.store.sweep(time.Now())
	if _, err := os.Lstat(s.store.metaPath(id)); err != nil {
		t.Fatalf("symlink should survive transient error: %v", err)
	}
}

func TestFreeBytes(t *testing.T) {
	s := testServer(t)
	free, err := s.store.freeBytes()
	if err != nil {
		t.Fatalf("freeBytes: %v", err)
	}
	if free <= 0 {
		t.Fatalf("freeBytes = %d", free)
	}
}

func TestMinFreeBytesBlocksUpload(t *testing.T) {
	s := testServer(t)
	allowLocal(s)
	s.cfg.MinFreeBytes = 1 << 60 // absurd floor -> always insufficient
	rec := putUpload(t, s, "http://x/f.txt", "data", "")
	if rec.Code != http.StatusInsufficientStorage {
		t.Fatalf("status = %d, want 507", rec.Code)
	}
}

// ---------- host canonicalization ----------

func TestPublicHost(t *testing.T) {
	s := testServer(t)
	s.cfg.Domains = []string{"files.example.com"}

	req := httptest.NewRequest(http.MethodGet, "http://files.example.com/x", nil)
	if got := s.publicHost(req); got != "files.example.com" {
		t.Fatalf("domain host = %q", got)
	}

	// spoofed host canonicalizes to configured domain
	req = httptest.NewRequest(http.MethodGet, "http://evil.example.org/x", nil)
	if got := s.publicHost(req); got != "files.example.com" {
		t.Fatalf("spoofed host = %q", got)
	}

	// IP literals pass through
	req = httptest.NewRequest(http.MethodGet, "http://1.2.3.4:8080/x", nil)
	if got := s.publicHost(req); got != "1.2.3.4:8080" {
		t.Fatalf("ip host = %q", got)
	}
}

func TestBaseURLXForwardedProto(t *testing.T) {
	s := testServer(t)
	s.cfg.BehindProxy = true
	req := httptest.NewRequest(http.MethodGet, "http://internal/x", nil)
	req.Host = "files.example.com"
	req.Header.Set("X-Forwarded-Proto", "https")
	if got := s.baseURL(req); got != "https://files.example.com" {
		t.Fatalf("baseURL = %q", got)
	}
	// garbage proto falls back to http
	req.Header.Set("X-Forwarded-Proto", "gopher")
	if got := s.baseURL(req); got != "http://files.example.com" {
		t.Fatalf("baseURL garbage = %q", got)
	}
}

func TestTLSPort(t *testing.T) {
	for addr, want := range map[string]string{
		":443": "443", "0.0.0.0:8443": "8443", "8443": "8443",
		"localhost": "443", "": "443", ":443 ": "443",
	} {
		if got := tlsPort(addr); got != want {
			t.Errorf("tlsPort(%q) = %q, want %q", addr, got, want)
		}
	}
}

func TestConfigSweepIntervalValidation(t *testing.T) {
	t.Setenv("SWEEP_INTERVAL", "-5m")
	if _, err := loadConfig(); err == nil {
		t.Error("expected error for negative SWEEP_INTERVAL")
	}
	t.Setenv("SWEEP_INTERVAL", "0")
	if _, err := loadConfig(); err == nil {
		t.Error("expected error for zero SWEEP_INTERVAL")
	}
	t.Setenv("SWEEP_INTERVAL", "")
	if _, err := loadConfig(); err != nil {
		t.Errorf("empty SWEEP_INTERVAL should be fine: %v", err)
	}
}

func TestStatusWriterReadFrom(t *testing.T) {
	rec := httptest.NewRecorder()
	sw := &statusWriter{ResponseWriter: rec}
	n, err := io.Copy(sw, strings.NewReader("hello world"))
	if err != nil || n != 11 {
		t.Fatalf("copy n=%d err=%v", n, err)
	}
	if sw.bytes != 11 || sw.status != 200 {
		t.Fatalf("bytes=%d status=%d", sw.bytes, sw.status)
	}
	if rec.Body.String() != "hello world" {
		t.Fatal("body mismatch")
	}
}
