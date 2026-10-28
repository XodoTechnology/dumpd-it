package main

import (
	"golang.org/x/crypto/acme/autocert"
	"log"
	"net/http"
	"os"
	"time"
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
				logLine("sweeper removed %d expired file(s)", n)
			}
		}
	}()

	if len(cfg.Domains) > 0 || cfg.CertFile != "" || cfg.SelfSigned {
		tlsCfg, err := s.tlsConfig()
		if err != nil {
			log.Fatalf("tls: %v", err)
		}
		srv := &http.Server{
			Addr:              cfg.TLSAddr,
			Handler:           s.logMiddleware(mux),
			TLSConfig:         tlsCfg,
			ReadHeaderTimeout: 30 * time.Second,
			IdleTimeout:       120 * time.Second,
		}
		if cfg.Addr != "" && cfg.Addr != "off" {
			go func() {
				hs := &http.Server{
					Addr:              cfg.Addr,
					Handler:           s.logMiddleware(s.httpFallback()),
					ReadHeaderTimeout: 30 * time.Second,
					IdleTimeout:       120 * time.Second,
				}
				log.Printf("http on %s (acme-challenge + https redirect)", cfg.Addr)
				if err := hs.ListenAndServe(); err != nil {
					logLine("http listener: %v", err)
				}
			}()
		}
		log.Printf("listening TLS on %s, data=%s ttl=%s", cfg.TLSAddr, cfg.DataDir, cfg.TTL)
		log.Fatal(srv.ListenAndServeTLS("", ""))
	}

	srv := &http.Server{
		Addr:              cfg.Addr,
		Handler:           s.logMiddleware(mux),
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	log.Printf("listening on %s, data=%s ttl=%s maxupload=%d", cfg.Addr, cfg.DataDir, cfg.TTL, cfg.MaxUpload)
	log.Fatal(srv.ListenAndServe())
}
