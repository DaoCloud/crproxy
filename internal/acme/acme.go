package acme

import (
	"context"
	"crypto/tls"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/wzshiming/hostmatcher"
	"golang.org/x/crypto/acme/autocert"
)

func hostWhitelist(hosts ...string) autocert.HostPolicy {
	matcher := hostmatcher.NewMatcher(hosts)
	return func(_ context.Context, host string) error {
		if !matcher.Match(host) {
			return fmt.Errorf("acme/autocert: host %q not configured in HostWhitelist", host)
		}
		return nil
	}
}

func NewAcme(domains []string, dir string) *tls.Config {
	m := &autocert.Manager{
		Prompt: autocert.AcceptTOS,
	}
	if len(domains) > 0 {
		m.HostPolicy = hostWhitelist(domains...)
	}
	if dir == "" {
		dir = cacheDir()
	}
	m.Cache = autocert.DirCache(dir)

	tlsConfig := m.TLSConfig()
	return tlsConfig
}

func homeDir() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("HOMEDRIVE") + os.Getenv("HOMEPATH")
	}
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return "/"
}

func cacheDir() string {
	const base = "autocert"
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(homeDir(), "Library", "Caches", base)
	case "windows":
		for _, ev := range []string{"APPDATA", "CSIDL_APPDATA", "TEMP", "TMP"} {
			if v := os.Getenv(ev); v != "" {
				return filepath.Join(v, base)
			}
		}
		// Worst case:
		return filepath.Join(homeDir(), base)
	}
	if xdg := os.Getenv("XDG_CACHE_HOME"); xdg != "" {
		return filepath.Join(xdg, base)
	}
	return filepath.Join(homeDir(), ".cache", base)
}
