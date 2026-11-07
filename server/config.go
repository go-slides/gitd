package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/go-browserhttp/browsergit/remote"
)

// Config is slides-gitd's configuration file (JSON, unknown fields refused).
// It names files for every secret and holds none: there is no field a token
// could be pasted into, and nothing is read from the environment.
type Config struct {
	// Listen is the address (loopback: Caddy is in front).
	Listen string `json:"listen"`
	// Origin is the playground's origin, the only one allowed to call.
	Origin string `json:"origin"`
	// TrustedProxies are the addresses (CIDR) whose identity headers are
	// believed; default loopback only.
	TrustedProxies []string `json:"trusted_proxies"`
	// ProxySecretFile, optional, holds a value Caddy adds to every request
	// (header_up X-Gitd-Proxy-Secret): a request without it is not from Caddy.
	ProxySecretFile string `json:"proxy_secret_file"`
	// MasterKeyFile holds the vault's 32-byte key (0600).
	MasterKeyFile string `json:"master_key_file"`
	// DataDir holds the vault.
	DataDir string `json:"data_dir"`
	// AuditFile is the append-only audit log.
	AuditFile string `json:"audit_file"`
	// Forges by name.
	Forges map[string]ForgeConfig `json:"forges"`
	// Users maps an OIDC subject to what it may reach. Deny by default: a
	// subject that is not here reaches nothing.
	Users map[string]User `json:"users"`
	// RatePerMinute and Burst bound each subject's mutating calls.
	RatePerMinute int `json:"rate_per_minute"`
	Burst         int `json:"burst"`
	// MaxBodyBytes bounds a request (default 64 MiB).
	MaxBodyBytes int64 `json:"max_body_bytes"`
}

// ForgeConfig is one forge.
type ForgeConfig struct {
	Kind string `json:"kind"` // github | gitlab | gitea
	API  string `json:"api"`
	Web  string `json:"web,omitempty"`
	// Auth: "github-app" (the App mints a token per repository) or
	// "user-token" (each user stores their own token, sealed in the vault).
	Auth string `json:"auth"`
	// GitHub App
	AppClientID    string `json:"app_client_id,omitempty"`
	InstallationID int64  `json:"installation_id,omitempty"`
	AppKeyFile     string `json:"app_key_file,omitempty"`
}

// User is one subject's grants.
type User struct {
	// Slug names the user's branches: slides/<slug>/... (default: derived).
	Slug string `json:"slug,omitempty"`
	// Repos are "forge:owner/name" the user may load from and propose to.
	Repos []string `json:"repos"`
}

// LoadConfig reads and checks path.
func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseConfig(b)
}

// ParseConfig decodes and checks a configuration.
func ParseConfig(b []byte) (*Config, error) {
	if len(b) > 1<<20 {
		return nil, errors.New("config: over 1 MiB")
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return &c, c.check()
}

func (c *Config) check() error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8091"
	}
	if c.Origin == "" || strings.HasSuffix(c.Origin, "/") || !strings.HasPrefix(c.Origin, "https://") && !strings.HasPrefix(c.Origin, "http://localhost") {
		return fmt.Errorf("config: origin %q must be an https origin without a path", c.Origin)
	}
	if len(c.TrustedProxies) == 0 {
		c.TrustedProxies = []string{"127.0.0.1/32", "::1/128"}
	}
	for _, p := range c.TrustedProxies {
		if _, err := netip.ParsePrefix(p); err != nil {
			return fmt.Errorf("config: trusted proxy %q: %v", p, err)
		}
	}
	if c.MasterKeyFile == "" || c.DataDir == "" || c.AuditFile == "" {
		return errors.New("config: master_key_file, data_dir and audit_file are required")
	}
	if c.RatePerMinute <= 0 {
		c.RatePerMinute = 30
	}
	if c.Burst <= 0 {
		c.Burst = 10
	}
	if c.MaxBodyBytes <= 0 {
		c.MaxBodyBytes = 64 << 20
	}
	for name, f := range c.Forges {
		if !forgeName.MatchString(name) {
			return fmt.Errorf("config: forge name %q", name)
		}
		switch f.Kind {
		case "github", "gitlab", "gitea":
		default:
			return fmt.Errorf("config: forge %s: kind %q", name, f.Kind)
		}
		switch f.Auth {
		case "user-token":
		case "github-app":
			if f.Kind != "github" || f.AppClientID == "" || f.InstallationID == 0 || f.AppKeyFile == "" {
				return fmt.Errorf("config: forge %s: github-app needs kind github, app_client_id, installation_id, app_key_file", name)
			}
		default:
			return fmt.Errorf("config: forge %s: auth %q", name, f.Auth)
		}
	}
	for sub, u := range c.Users {
		if sub == "" {
			return errors.New("config: empty subject")
		}
		if u.Slug != "" && !slugRe.MatchString(u.Slug) {
			return fmt.Errorf("config: user %s: slug %q", sub, u.Slug)
		}
		for _, r := range u.Repos {
			f, repo, ok := strings.Cut(r, ":")
			if !ok {
				return fmt.Errorf("config: user %s: repo %q is not forge:owner/name", sub, r)
			}
			fc, known := c.Forges[f]
			if !known {
				return fmt.Errorf("config: user %s: unknown forge %q", sub, f)
			}
			if err := remote.CheckRepo(repo, fc.Kind == "gitlab"); err != nil {
				return fmt.Errorf("config: user %s: %v", sub, err)
			}
		}
	}
	return nil
}
