// Command slides-gitd serves the go-slides playground's git operations on a
// self-hosted deployment, behind Caddy and oauth2-proxy.
//
//	slides-gitd serve --config /etc/slides-gitd/config.json
//
// Every secret is read from a file named in the configuration (the vault's
// master key, a GitHub App's private key, the proxy secret); none is taken
// from a flag or the environment, where it would show in ps, /proc or a
// crash report.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/go-browserhttp/browsergit/secret"
	"github.com/go-slides/gitd/internal/audit"
	"github.com/go-slides/gitd/internal/ghapp"
	"github.com/go-slides/gitd/internal/vault"
	"github.com/go-slides/gitd/server"
	"github.com/spf13/cobra"
)

var osExit = os.Exit

func main() {
	if err := RootCmd().Execute(); err != nil {
		osExit(1)
	}
}

// RootCmd is the command tree.
func RootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "slides-gitd",
		Short:         "The go-slides playground's git backend: credentials stay on the server",
		SilenceUsage:  true,
		SilenceErrors: false,
	}
	var configPath string
	serve := &cobra.Command{
		Use:   "serve",
		Short: "Serve the API (behind Caddy and oauth2-proxy)",
		RunE: func(cmd *cobra.Command, _ []string) error {
			srv, cfg, err := Build(configPath)
			if err != nil {
				return err
			}
			return run(cmd.Context(), cmd.OutOrStdout(), srv, cfg)
		},
	}
	serve.Flags().StringVarP(&configPath, "config", "c", "/etc/slides-gitd/config.json", "configuration file")
	check := &cobra.Command{
		Use:   "check",
		Short: "Check the configuration and the secret files, then exit",
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, cfg, err := Build(configPath)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "ok: %d forges, %d users, listening on %s\n", len(cfg.Forges), len(cfg.Users), cfg.Listen)
			return nil
		},
	}
	check.Flags().StringVarP(&configPath, "config", "c", "/etc/slides-gitd/config.json", "configuration file")
	root.AddCommand(serve, check)
	return root
}

// readSecretFile reads a small secret from a file only its owner can read.
func readSecretFile(path string) (secret.Token, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return secret.Token{}, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm()&0o077 != 0 || st.Size() > 4096 {
		return secret.Token{}, fmt.Errorf("%s must be a regular file under 4 KiB readable by its owner only", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return secret.Token{}, err
	}
	return secret.New(strings.TrimSpace(string(b))), nil
}

// Build loads the configuration and every secret, and assembles the server.
func Build(configPath string) (*server.Server, *server.Config, error) {
	cfg, err := server.LoadConfig(configPath)
	if err != nil {
		return nil, nil, err
	}
	key, err := vault.LoadKey(cfg.MasterKeyFile)
	if err != nil {
		return nil, nil, err
	}
	v, err := vault.Open(cfg.DataDir, key)
	clear(key)
	if err != nil {
		return nil, nil, err
	}
	a, err := audit.Open(cfg.AuditFile)
	if err != nil {
		return nil, nil, err
	}
	apps := map[string]*ghapp.App{}
	for name, f := range cfg.Forges {
		if f.Auth != "github-app" {
			continue
		}
		k, err := ghapp.LoadKey(f.AppKeyFile)
		if err != nil {
			return nil, nil, fmt.Errorf("forge %s: %w", name, err)
		}
		apps[name] = ghapp.New(f.API, f.AppClientID, f.InstallationID, k)
	}
	var proxySecret secret.Token
	if cfg.ProxySecretFile != "" {
		if proxySecret, err = readSecretFile(cfg.ProxySecretFile); err != nil {
			return nil, nil, err
		}
	}
	return server.New(cfg, v, a, apps, proxySecret), cfg, nil
}

func run(ctx context.Context, out io.Writer, srv *server.Server, cfg *server.Config) error {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	hs := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      5 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	errc := make(chan error, 1)
	go func() { errc <- hs.ListenAndServe() }()
	// expired sessions nobody presents again are swept (go-slides/gitd#6)
	go func() {
		t := time.NewTicker(5 * time.Minute)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				srv.Sessions().Sweep()
			}
		}
	}()
	fmt.Fprintf(out, "slides-gitd listening on %s\n", cfg.Listen)
	select {
	case err := <-errc:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		sctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		return hs.Shutdown(sctx)
	}
}
