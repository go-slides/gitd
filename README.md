# slides-gitd

The git backend for a **self-hosted** go-slides playground. It loads a deck's
folder from a forge, proposes changes as a new branch and a pull (merge)
request, and checks for upstream changes, while the forge credentials **stay on
the server**. The browser holds only an HttpOnly session cookie.

It sits behind Caddy and oauth2-proxy (OIDC). For the public playground, which
talks to GitHub and GitLab from the browser, see
[go-browserhttp/browsergit](https://github.com/go-browserhttp/browsergit).

```
browser ──https──▶ Caddy ── forward_auth ──▶ oauth2-proxy ──▶ your IdP (OIDC)
                     │  X-Auth-Request-User (sub), X-Gitd-Proxy-Secret
                     └──────────────▶ slides-gitd 127.0.0.1:8091 ──▶ GitHub / GitLab / Gitea
```

## API

| | |
|---|---|
| `GET /api/git/session` | Creates or returns this user's session. Sets `__Host-gitd` and returns the CSRF token and the repositories the user may use. |
| `POST /api/git/credential` | Stores the user's own token for a `user-token` forge, sealed. It is never sent back. |
| `POST /api/git/credential/delete` | Forgets it. |
| `POST /api/git/load` | `{forge, repo, ref, dir}` → `{files, base}` |
| `POST /api/git/propose` | `{forge, base, files, title, body}` → `{branch, url}`. The **server** names the branch: `slides/<user>-<hash>/<title>-<time>`. |
| `POST /api/git/refresh` | `{forge, base}` → `{files, base}` (`files` is null when nothing moved). |

## Security

Each point has a test that fails if it is broken.

- **Identity comes from the proxy only.** The request must come from a
  trusted address (loopback by default) and carry `X-Gitd-Proxy-Secret` when it
  is configured. The subject is `X-Auth-Request-User`, which oauth2-proxy fills
  with the OIDC `sub` by default (`providers/provider_data.go`, `UserClaim`).
  With no identity the answer is 401, so an expired IdP session reaches nothing.
- **User A can never use user B's session or token.**
  - A session is bound to one subject. Another subject's cookie is refused,
    *and the session is destroyed*.
  - Session ids come from the server (32 random bytes), so a client-chosen id
    is replaced, never adopted.
  - The CSRF token is per session and compared in constant time.
  - Tests cover a cookie swap, a mixed cookie and CSRF token, a guessed id,
    fixation, a change of identity behind the browser, and 200 concurrent
    requests from two users, each of which must use its own credential.
- **CSRF**: every mutating call needs:
  - `POST` with the exact configured `Origin`;
  - `X-Requested-With: slides-gitd`;
  - a JSON body;
  - the session cookie (`Secure`, `HttpOnly`, `SameSite=Strict`, `__Host-`);
  - the `X-CSRF-Token` header.
- **Deny by default.** A subject reaches only the `forge:owner/name` entries the
  configuration grants it.
- **Writes only to `slides/<user>-<hash>/*`.** `<user>` is the configured slug or
  one derived from the subject, and `<hash>` is 10 hex digits of
  SHA-256(subject), so no two subjects share a directory. Startup refuses
  duplicate configured slugs and coinciding directories. The branch name is the server's, and a
  request field naming a branch is an unknown field, refused. The forge
  adapter enforces the prefix again and never writes to an existing or
  default branch.
- **Credentials are encrypted at rest with one key per user.**
  - Each record is AES-256-GCM. Its key is derived with HKDF-SHA256 from the
    master key and the subject, and its additional data binds it to the
    subject and the forge.
  - A record copied to another user, renamed to another forge, or read with
    another master key does not open.
  - Directory names are hashes; files are `0600` and directories `0700`.
    Writes are atomic.
- **GitHub uses an App.** Its installation token is minted **for the one
  repository** of the call, with `contents:write`, `pull_requests:write` and
  `metadata:read` only. It lives an hour and is cached until five minutes
  before expiry.
- **Secrets come from files only.** These are the master key, the App's
  private key and the proxy secret. Each file must be readable by its owner
  only. No flag takes a secret, nothing is read from the environment, and a
  secret pasted into the configuration is an unknown field.
- **Limits**: a per-user token bucket (429), a bound on the request body, and
  timeouts on the HTTP server.
- **Audit**: one JSON line per call (who, what, where, the outcome as a
  class). It never holds file content, a token, a cookie or an error's text.
- **Fuzzed**: every request body. Chaos tests cover a client killed in the
  middle of a proposal (the proposal is canceled and audited, and the next one
  works), concurrent users, and concurrent writers to the vault.
- `govulncheck` runs on every push and daily.

## Configuration

```json
{
  "listen": "127.0.0.1:8091",
  "origin": "https://slides.example.org",
  "proxy_secret_file": "/etc/slides-gitd/proxy.secret",
  "master_key_file": "/etc/slides-gitd/master.key",
  "data_dir": "/var/lib/slides-gitd",
  "audit_file": "/var/log/slides-gitd/audit.log",
  "forges": {
    "github": {"kind": "github", "api": "https://api.github.com", "auth": "github-app",
               "app_client_id": "Iv1.…", "installation_id": 12345678,
               "app_key_file": "/etc/slides-gitd/github-app.pem"},
    "gitlab": {"kind": "gitlab", "api": "https://gitlab.example.org/api/v4", "auth": "user-token"}
  },
  "users": {
    "3f2b…-oidc-sub": {"slug": "ada", "repos": ["github:lab/talks", "gitlab:team/slides"]}
  }
}
```

Create the master key with `head -c 32 /dev/urandom > master.key && chmod 600 master.key`.
Then run `slides-gitd check -c config.json`, which loads every secret file and
exits, followed by `slides-gitd serve -c config.json`.

### Caddy and oauth2-proxy

```caddyfile
slides.example.org {
    handle /oauth2/* {
        reverse_proxy 127.0.0.1:4180
    }
    handle /api/git/* {
        # never let a client choose its identity, whatever Caddy's version does
        request_header -X-Auth-Request-User
        request_header -X-Auth-Request-Email
        request_header -X-Gitd-Proxy-Secret
        forward_auth 127.0.0.1:4180 {
            uri /oauth2/auth
            copy_headers X-Auth-Request-User X-Auth-Request-Email
        }
        request_body { max_size 64MB }
        reverse_proxy 127.0.0.1:8091 {
            header_up X-Gitd-Proxy-Secret {file./etc/caddy/gitd-proxy.secret}
        }
    }
    handle { root * /srv/slides; file_server }
}
```

Run oauth2-proxy with `--set-xauthrequest` and your IdP.
- The client's own identity headers are deleted before `forward_auth` runs.
  Current Caddy also deletes a client-supplied header before `copy_headers`
  (`forwardauth/caddyfile.go`), but older versions did not, so the explicit
  `request_header -…` lines stay.
- `{file.*}` reads the proxy secret from a file (Caddy placeholders), so it is
  not in an environment variable.

### Registering the forges (needs your accounts)

- **GitHub App:** go to Settings ▸ Developer settings ▸ GitHub Apps ▸ New.
  - Permissions: Contents read & write, Pull requests read & write, Metadata
    read. No webhook.
  - Install it on the organisation, on the deck repositories only.
  - Put the client ID and the installation ID in the configuration, and the
    private key in `app_key_file` (`chmod 600`).
- **GitLab:** each user stores a personal or project access token with scope
  **`api`**. GitLab's REST API only accepts `api` for writes. `write_repository`
  "does not support API authentication" (it covers git over HTTP only, and
  GitLab serves git over HTTP without CORS). `api` grants "complete read and
  write access to the API" for the token's user, so a stolen token can do
  anything that user can.
  - Prefer a **project or group access token** scoped to the deck
    repositories (they carry `api` without the Git-over-HTTP clause and only
    for that project or group).
  - Otherwise use a dedicated GitLab account that is a member of those
    projects only.
  - Source: [GitLab, access token scopes](https://docs.gitlab.com/security/tokens/access_token_scopes/).

## Licence

BSD-3-Clause.
