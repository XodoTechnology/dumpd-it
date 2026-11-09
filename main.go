package main

import (
	"context"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type server struct {
	cfg   *Config
	store *store
	acme  *autocert.Manager
}

func logLine(format string, args ...any) {
	log.Printf(format, args...)
}

type statusWriter struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	n, err := w.ResponseWriter.Write(b)
	w.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// Flush delegates to the underlying writer when it supports flushing.
func (w *statusWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// ReadFrom preserves zero-copy paths (e.g. sendfile) of the underlying
// writer while still counting bytes for the request log.
func (w *statusWriter) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		n, err := rf.ReadFrom(r)
		w.bytes += int(n)
		if w.status == 0 {
			w.status = http.StatusOK
		}
		return n, err
	}
	// io.Copy would recurse through ReadFrom; hide it behind a Writer-only view.
	return io.Copy(struct{ io.Writer }{w}, r)
}

func (s *server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w}
		start := time.Now()
		next.ServeHTTP(sw, r)
		log.Printf("%s %s %s -> %d %dB %s",
			s.clientIP(r), r.Method, r.URL.Path, sw.status, sw.bytes,
			time.Since(start).Round(time.Microsecond))
	})
}

func main() {
	log.SetOutput(os.Stdout)
	log.SetFlags(log.LstdFlags | log.LUTC)

	cfg, err := loadConfig()
	if err != nil {
		log.Fatalf("config: %v", err)
	}
	if len(cfg.AllowNets) == 0 {
		log.Printf("WARNING: UPLOAD_ALLOW is empty - all uploads will be rejected")
	}
	st, err := newStore(cfg.DataDir)
	if err != nil {
		log.Fatalf("store: %v", err)
	}
	s := &server{cfg: cfg, store: st}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", s.index)
	mux.HandleFunc("GET /healthz", s.healthz)
	mux.HandleFunc("PUT /{name...}", s.upload)
	mux.HandleFunc("POST /{name...}", s.upload)
	mux.HandleFunc("GET /d/{id}", s.download)
	mux.HandleFunc("GET /d/{id}/{filename...}", s.download)
	mux.HandleFunc("DELETE /d/{id}", s.del)
	mux.HandleFunc("DELETE /d/{id}/{filename...}", s.del)

	go func() {
		s.store.sweep(time.Now())
		for range time.Tick(cfg.SweepEvery) {
			if n := s.store.sweep(time.Now()); n > 0 {
				logLine("sweeper removed %d item(s)", n)
			}
		}
	}()

	var primary *http.Server
	var extras []*http.Server

	if len(cfg.Domains) > 0 || cfg.CertFile != "" || cfg.SelfSigned {
		tlsCfg, err := s.tlsConfig()
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
		primary = &http.Server{
			Addr:              cfg.TLSAddr,
			Handler:           s.logMiddleware(mux),
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		if cfg.Addr != "" && cfg.Addr != "off" {
			hs := &http.Server{
				Addr:              cfg.Addr,
				Handler:           s.logMiddleware(s.httpFallback()),
				ReadHeaderTimeout: 30 * time.Second,
				IdleTimeout:       120 * time.Second,
			}
			extras = append(extras, hs)
			go func() {
				log.Printf("http on %s (acme-challenge + https redirect)", cfg.Addr)
				if err := hs.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
					logLine("http listener: %v", err)
				}
			}()
		}
		log.Printf("listening TLS on %s, data=%s ttl=%s", cfg.TLSAddr, cfg.DataDir, cfg.TTL)
	} else {
		primary = &http.Server{
			Addr:              cfg.Addr,
			Handler:           s.logMiddleware(mux),
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		log.Printf("listening on %s, data=%s ttl=%s maxupload=%d", cfg.Addr, cfg.DataDir, cfg.TTL, cfg.MaxUpload)
	}

	servers := append([]*http.Server{primary}, extras...)
	errCh := make(chan error, 1)
	go func() {
		var err error
		if primary.TLSConfig != nil {
			err = primary.ListenAndServeTLS("", "")
		} else {
			err = primary.ListenAndServe()
		}
		errCh <- err
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	select {
	case <-ctx.Done():
		log.Printf("shutting down")
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("serve: %v", err)
		}
	}

	sctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for _, srv := range servers {
		if err := srv.Shutdown(sctx); err != nil {
			logLine("shutdown %s: %v", srv.Addr, err)
		}
	}
}
