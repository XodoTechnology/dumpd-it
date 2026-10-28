package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// tlsConfig builds the TLS config for whichever cert mode is configured:
// manual CERT_FILE/KEY_FILE > ACME via DOMAIN > SELF_SIGNED.
func (s *server) tlsConfig() (*tls.Config, error) {
	switch {
	case s.cfg.CertFile != "":
		cert, err := tls.LoadX509KeyPair(s.cfg.CertFile, s.cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("load cert: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil

	case len(s.cfg.Domains) > 0 && !s.cfg.SelfSigned:
		cacheDir := filepath.Join(s.cfg.DataDir, "acme")
		if err := os.MkdirAll(cacheDir, 0o700); err != nil {
			return nil, err
		}
		m := &autocert.Manager{
			Cache:      autocert.DirCache(cacheDir),
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(s.cfg.Domains...),
			Email:      s.cfg.ACMEEmail,
		}
		if s.cfg.ACMEStaging {
			m.Client = &acme.Client{DirectoryURL: "https://acme-staging-v02.api.letsencrypt.org/directory"}
		}
		s.acme = m
		logLine("ACME (Let's Encrypt) enabled for: %s", strings.Join(s.cfg.Domains, ", "))
		return &tls.Config{GetCertificate: m.GetCertificate}, nil

	default:
		cert, err := loadOrCreateSelfSigned(s.cfg.DataDir, s.cfg.Domains)
		if err != nil {
			return nil, fmt.Errorf("self-signed cert: %w", err)
		}
		logLine("using self-signed certificate")
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}
}

// httpFallback answers /healthz directly, satisfies ACME http-01 challenges
// when a manager is active, and redirects everything else to https.
func (s *server) httpFallback() http.Handler {
	var inner http.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+r.Host+r.URL.RequestURI(), http.StatusMovedPermanently)
	})
	if s.acme != nil {
		inner = s.acme.HTTPHandler(nil)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			io.WriteString(w, "ok\n")
			return
		}
		inner.ServeHTTP(w, r)
	})
}

// loadOrCreateSelfSigned returns a persistent self-signed cert from
// <dataDir>/tls, generating one (10y, ECDSA P-256) if absent.
func loadOrCreateSelfSigned(dir string, domains []string) (tls.Certificate, error) {
	dir = filepath.Join(dir, "tls")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	certPath := filepath.Join(dir, "cert.pem")
	keyPath := filepath.Join(dir, "key.pem")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	var dns []string
	ips := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, h := range append([]string{"localhost"}, domains...) {
		if ip := net.ParseIP(h); ip != nil {
			ips = append(ips, ip)
		} else {
			dns = append(dns, h)
		}
	}
	cn := "dumpd"
	if len(dns) > 0 {
		cn = dns[0]
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(now.UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dns,
		IPAddresses:           ips,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return tls.Certificate{}, err
	}
	return tls.X509KeyPair(certPEM, keyPEM)
}
