package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

type Meta struct {
	ID         string    `json:"id"`
	Filename   string    `json:"filename"`
	Size       int64     `json:"size"`
	StoredSize int64     `json:"stored_size"`
	SHA256     string    `json:"sha256"`
	Gzipped    bool      `json:"gzipped"`
	Downloads  int64     `json:"downloads"`
	Created    time.Time `json:"created"`
	Expires    time.Time `json:"expires"`
	DeleteKey  string    `json:"delete_key"`
}

type store struct {
	dir      string
	blobDir  string
	metaDir  string
	tmpDir   string
	metaLock sync.Mutex
}

func newStore(dir string) (*store, error) {
	s := &store{
		dir:     dir,
		blobDir: filepath.Join(dir, "blobs"),
		metaDir: filepath.Join(dir, "meta"),
		tmpDir:  filepath.Join(dir, "tmp"),
	}
	for _, d := range []string{s.blobDir, s.metaDir, s.tmpDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	return s, nil
}

var idRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,24}$`)

func validID(id string) bool { return idRe.MatchString(id) }

func newToken(nbytes int) string {
	b := make([]byte, nbytes)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *store) blobPath(id string) string { return filepath.Join(s.blobDir, id) }
func (s *store) metaPath(id string) string { return filepath.Join(s.metaDir, id+".json") }

var errCorruptMeta = errors.New("corrupt meta file")

func (s *store) loadMeta(id string) (*Meta, error) {
	if !validID(id) {
		return nil, fmt.Errorf("bad id")
	}
	b, err := os.ReadFile(s.metaPath(id))
	if err != nil {
		return nil, err
	}
	var m Meta
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, fmt.Errorf("%w: %s", errCorruptMeta, err)
	}
	return &m, nil
}

// writeMeta atomically persists m. Caller must hold metaLock (or be in upload
// path where no concurrent access is possible yet).
func (s *store) writeMeta(m *Meta) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(s.metaDir, ".m-*")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), s.metaPath(m.ID))
}

// touch bumps the download counter and rolls the expiry forward.
func (s *store) touch(m *Meta, ttl time.Duration) {
	s.metaLock.Lock()
	defer s.metaLock.Unlock()
	m.Downloads++
	m.Expires = time.Now().Add(ttl)
	if err := s.writeMeta(m); err != nil {
		logLine("meta-write id=%s err=%v", m.ID, err)
	}
}

func (s *store) delete(id string) {
	os.Remove(s.blobPath(id))
	os.Remove(s.metaPath(id))
}

const (
	// orphanGrace keeps freshly-written blobs safe from the orphan sweeper:
	// an upload renames the blob into place a moment before writeMeta lands.
	orphanGrace = 10 * time.Minute
	// tmpMaxAge reclaims temp files left behind by uploads killed mid-write.
	tmpMaxAge = 24 * time.Hour
)

// sweep removes expired files, corrupt metas, orphaned blobs and stale temp
// files; returns the number of filesystem entries removed.
func (s *store) sweep(now time.Time) int {
	n := s.sweepMeta(now)
	n += s.sweepBlobs(now)
	n += s.sweepTmp(now)
	return n
}

func (s *store) sweepMeta(now time.Time) int {
	ents, err := os.ReadDir(s.metaDir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		id := strings.TrimSuffix(e.Name(), ".json")
		if e.IsDir() || id == e.Name() || !validID(id) {
			continue
		}
		m, err := s.loadMeta(id)
		switch {
		case err == nil && !now.After(m.Expires):
			continue
		case err != nil && !errors.Is(err, errCorruptMeta) && !os.IsNotExist(err):
			// transient failure (permissions, EMFILE, ...): keep and retry next tick
			logLine("sweep: keeping %s: %v", id, err)
			continue
		}
		s.delete(id)
		n++
	}
	return n
}

// sweepBlobs removes blobs that have no meta file (crash between blob rename
// and meta write, or manual meta deletion). Entries younger than orphanGrace
// are left alone to cover the upload rename window.
func (s *store) sweepBlobs(now time.Time) int {
	ents, err := os.ReadDir(s.blobDir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		if _, err := os.Stat(s.metaPath(e.Name())); err == nil {
			continue // meta exists
		} else if !os.IsNotExist(err) {
			continue // can't tell - keep
		}
		if fi, err := e.Info(); err != nil || now.Sub(fi.ModTime()) < orphanGrace {
			continue
		}
		if os.Remove(s.blobPath(e.Name())) == nil {
			n++
		}
	}
	return n
}

// sweepTmp removes temp files abandoned by uploads that died mid-write.
func (s *store) sweepTmp(now time.Time) int {
	ents, err := os.ReadDir(s.tmpDir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range ents {
		if e.IsDir() {
			continue
		}
		fi, err := e.Info()
		if err != nil || now.Sub(fi.ModTime()) < tmpMaxAge {
			continue
		}
		if os.Remove(filepath.Join(s.tmpDir, e.Name())) == nil {
			n++
		}
	}
	return n
}
