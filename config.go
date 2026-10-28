package main

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Addr        string
	TLSAddr     string
	DataDir     string
	BaseURL     string
	AllowNets   []netip.Prefix
	BehindProxy bool
	MaxUpload   int64
	UnlockKey   string
	TTL         time.Duration
	SweepEvery  time.Duration
	CertFile    string
	KeyFile     string
	Domains     []string
	SelfSigned  bool
	ACMEStaging bool
	ACMEEmail   string
}

func loadConfig() (*Config, error) {
	c := &Config{
		DataDir:     envStr("DATA_DIR", "./data"),
		TLSAddr:     envStr("TLS_ADDR", ":443"),
		BaseURL:     strings.TrimRight(os.Getenv("BASE_URL"), "/"),
		BehindProxy: envBool("BEHIND_PROXY", false),
		MaxUpload:   envInt64("MAX_UPLOAD_MB", 10240) << 20,
		UnlockKey:   os.Getenv("UNLOCK_KEY"),
		SweepEvery:  envDur("SWEEP_INTERVAL", 10*time.Minute),
		CertFile:    os.Getenv("CERT_FILE"),
		KeyFile:     os.Getenv("KEY_FILE"),
		SelfSigned:  envBool("SELF_SIGNED", false),
		ACMEStaging: envBool("ACME_STAGING", false),
		ACMEEmail:   os.Getenv("ACME_EMAIL"),
	}

	for _, d := range strings.Split(os.Getenv("DOMAIN"), ",") {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			c.Domains = append(c.Domains, d)
		}
	}
	if tlsMode := len(c.Domains) > 0 || c.CertFile != "" || c.SelfSigned; tlsMode {
		c.Addr = envStr("ADDR", ":80") // http side: acme challenge + redirect
	} else {
		c.Addr = envStr("ADDR", ":8080")
	}

	var err error
	if c.TTL, err = time.ParseDuration(envStr("TTL", "168h")); err != nil {
		return nil, fmt.Errorf("invalid TTL: %w", err)
	}
	if c.TTL <= 0 {
		return nil, fmt.Errorf("TTL must be positive")
	}
	if c.MaxUpload <= 0 {
		return nil, fmt.Errorf("MAX_UPLOAD_MB must be positive")
	}

	for _, tok := range strings.Split(os.Getenv("UPLOAD_ALLOW"), ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if p, err := netip.ParsePrefix(tok); err == nil {
			c.AllowNets = append(c.AllowNets, p.Masked())
			continue
		}
		if a, err := netip.ParseAddr(tok); err == nil {
			c.AllowNets = append(c.AllowNets, netip.PrefixFrom(a, a.BitLen()))
			continue
		}
		return nil, fmt.Errorf("invalid UPLOAD_ALLOW entry %q (want IP or CIDR)", tok)
	}
	if (c.CertFile == "") != (c.KeyFile == "") {
		return nil, fmt.Errorf("CERT_FILE and KEY_FILE must be set together")
	}
	return c, nil
}

func envStr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	if v := os.Getenv(k); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envInt64(k string, def int64) int64 {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			return n
		}
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
