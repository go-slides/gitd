// Package vault keeps each user's forge tokens encrypted at rest, one key per
// user.
//
// A record is AES-256-GCM sealed with a key derived for its user alone
// (HKDF-SHA256 over the master key, info "slides-gitd/v1/user/" + subject), and
// its additional data binds it to that user and forge. A record copied into
// another user's directory, or renamed to another forge, does not open: the
// key and the additional data both differ. The master key comes from a file
// readable by its owner only; it is never logged, never in argv, never in the
// environment.
package vault

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-browserhttp/browsergit/secret"
)

// Errors.
var (
	ErrNotFound = errors.New("vault: no credential")
	ErrCorrupt  = errors.New("vault: record does not open")
	ErrKeyFile  = errors.New("vault: master key file refused")
	ErrName     = errors.New("vault: bad subject or forge name")
)

// MaxToken bounds a stored token.
const MaxToken = 4096

const version = 1

// Vault is a directory of sealed records.
type Vault struct {
	dir    string
	master []byte
}

// LoadKey reads a 32-byte master key (raw, or 64 hex characters) from path. The
// file must be a regular file that neither group nor others can read.
func LoadKey(path string) ([]byte, error) {
	st, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyFile, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrKeyFile, path)
	}
	if st.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%w: %s is readable by group or others (mode %v)", ErrKeyFile, path, st.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyFile, err)
	}
	s := strings.TrimSpace(string(b))
	if len(s) == 64 {
		if k, err := hex.DecodeString(s); err == nil {
			return k, nil
		}
	}
	if len(b) == 32 {
		return b, nil
	}
	return nil, fmt.Errorf("%w: want 32 bytes or 64 hex characters", ErrKeyFile)
}

// Open returns the vault in dir (created 0700) with master key.
func Open(dir string, master []byte) (*Vault, error) {
	if len(master) != 32 {
		return nil, fmt.Errorf("%w: master key must be 32 bytes", ErrKeyFile)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// an existing directory keeps its mode under MkdirAll: tighten it
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	return &Vault{dir: dir, master: append([]byte(nil), master...)}, nil
}

var forgeName = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

func check(subject, forge string) error {
	if subject == "" || len(subject) > 256 || !forgeName.MatchString(forge) {
		return ErrName
	}
	return nil
}

// userDir is the user's directory: a hash of the subject, so no subject can
// name a path.
func (v *Vault) userDir(subject string) string {
	h := sha256.Sum256([]byte("slides-gitd/v1/dir/" + subject))
	return filepath.Join(v.dir, hex.EncodeToString(h[:16]))
}

func (v *Vault) aead(subject string) (cipher.AEAD, error) {
	key, err := hkdf.Key(sha256.New, v.master, nil, "slides-gitd/v1/user/"+subject, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func aad(subject, forge string) []byte {
	return []byte(fmt.Sprintf("slides-gitd/v%d\x00%s\x00%s", version, subject, forge))
}

// Put seals tok for subject and forge, replacing any previous record
// atomically (a crash leaves the old record or the new one, never half).
func (v *Vault) Put(subject, forge string, tok secret.Token) error {
	if err := check(subject, forge); err != nil {
		return err
	}
	if tok.IsZero() || len(tok.Reveal()) > MaxToken {
		return fmt.Errorf("vault: token empty or over %d bytes", MaxToken)
	}
	g, err := v.aead(subject)
	if err != nil {
		return err
	}
	nonce := make([]byte, g.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	rec := append([]byte{version}, nonce...)
	rec = g.Seal(rec, nonce, []byte(tok.Reveal()), aad(subject, forge))
	dir := v.userDir(subject)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(rec); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), filepath.Join(dir, forge+".rec"))
}

// Get opens subject's record for forge.
func (v *Vault) Get(subject, forge string) (secret.Token, error) {
	if err := check(subject, forge); err != nil {
		return secret.Token{}, err
	}
	rec, err := os.ReadFile(filepath.Join(v.userDir(subject), forge+".rec"))
	if errors.Is(err, fs.ErrNotExist) {
		return secret.Token{}, ErrNotFound
	}
	if err != nil {
		return secret.Token{}, err
	}
	g, err := v.aead(subject)
	if err != nil {
		return secret.Token{}, err
	}
	if len(rec) < 1+g.NonceSize()+g.Overhead() || rec[0] != version || len(rec) > 1+g.NonceSize()+g.Overhead()+MaxToken {
		return secret.Token{}, ErrCorrupt
	}
	nonce := rec[1 : 1+g.NonceSize()]
	plain, err := g.Open(nil, nonce, rec[1+g.NonceSize():], aad(subject, forge))
	if err != nil {
		return secret.Token{}, ErrCorrupt
	}
	tok := secret.New(string(plain))
	clear(plain)
	return tok, nil
}

// Delete removes subject's record for forge; an absent record is not an error.
func (v *Vault) Delete(subject, forge string) error {
	if err := check(subject, forge); err != nil {
		return err
	}
	err := os.Remove(filepath.Join(v.userDir(subject), forge+".rec"))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
