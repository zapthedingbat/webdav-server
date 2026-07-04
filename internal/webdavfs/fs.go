package webdavfs

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/zapthedingbat/webdav-server/internal/config"
	"github.com/zapthedingbat/webdav-server/internal/ldapauth"
	"golang.org/x/net/webdav"
)

type contextKey string

const userContextKey contextKey = "user"

func WithUser(ctx context.Context, u *User) context.Context {
	return context.WithValue(ctx, userContextKey, u)
}

func UserFromContext(ctx context.Context) *User {
	u, _ := ctx.Value(userContextKey).(*User)
	return u
}

type User struct {
	UID        string
	Username   string
	Mail       string
	CN         string
	EmailLocal string
	Groups     []string
}

type Permissions struct {
	Read   bool
	Write  bool
}

func expandPathPlaceholders(fsPath string, user *User) string {
	s := fsPath
	s = strings.ReplaceAll(s, "%uid%", user.UID)
	s = strings.ReplaceAll(s, "%username%", user.Username)
	s = strings.ReplaceAll(s, "%mail%", user.Mail)
	s = strings.ReplaceAll(s, "%cn%", user.CN)
	s = strings.ReplaceAll(s, "%email_local%", user.EmailLocal)
	return s
}

type VirtualFS struct {
	cfg *config.Config
}

func NewVirtualFS(cfg *config.Config) *VirtualFS {
	return &VirtualFS{cfg: cfg}
}

func (v *VirtualFS) userCanAccessCollection(col *config.Collection, user *User) bool {
	if col.Home {
		return true
	}
	acl := findACLForSub(col, ".")
	return acl != nil && effectivePerms(acl, user).Read
}

func (v *VirtualFS) resolve(ctx context.Context, name string) (string, Permissions, bool) {
	user := UserFromContext(ctx)
	if user == nil {
		return "", Permissions{}, false
	}

	name = strings.Trim(path.Clean("/"+name), "/")
	if name == "" {
		return "", Permissions{}, false
	}

	parts := strings.SplitN(name, "/", 2)
	top := parts[0]
	sub := ""
	if len(parts) == 2 {
		sub = parts[1]
	}

	for i := range v.cfg.Collections {
		col := &v.cfg.Collections[i]
		collectionPath := strings.Trim(col.Path, "/")
		if collectionPath == "" || collectionPath != top {
			continue
		}

		if col.Home {
			base := filepath.Clean(expandPathPlaceholders(col.FSPath, user))
			if err := os.MkdirAll(base, 0755); err != nil {
				return "", Permissions{}, false
			}
			realPath := filepath.Join(base, filepath.FromSlash(sub))
			return realPath, Permissions{Read: true, Write: true}, true
		}

		base := filepath.Clean(col.FSPath)
		return v.resolveACL(col, base, sub, user)
	}

	return "", Permissions{}, false
}

func modePermissions(mode string) (Permissions, bool) {
	s := strings.TrimSpace(strings.ToLower(mode))
	switch s {
	case "r":
		return Permissions{Read: true}, true
	case "w":
		return Permissions{Write: true}, true
	case "rw", "wr":
		return Permissions{Read: true, Write: true}, true
	default:
		return Permissions{}, false
	}
}

func effectivePerms(acl *config.CollectionACL, user *User) Permissions {
	var p Permissions

	for _, pr := range acl.Rules {
		matched := false
		if strings.HasPrefix(pr.Principal, "user:") {
			matched = strings.TrimPrefix(pr.Principal, "user:") == user.UID
		} else if strings.HasPrefix(pr.Principal, "group:") {
			dn := strings.TrimPrefix(pr.Principal, "group:")
			for _, g := range user.Groups {
				if g == dn {
					matched = true
					break
				}
			}
		}
		if !matched {
			continue
		}

		modePerms, ok := modePermissions(pr.Mode)
		if !ok {
			continue
		}
		p.Read = p.Read || modePerms.Read
		p.Write = p.Write || modePerms.Write
	}

	return p
}

func findACLForSub(col *config.Collection, sub string) *config.CollectionACL {
	sub = strings.Trim(path.Clean("/"+sub), "/")
	if sub == "" {
		sub = "."
	}

	var best *config.CollectionACL
	bestLen := -1
	for i := range col.ACLs {
		acl := &col.ACLs[i]
		p := strings.Trim(path.Clean("/"+acl.Path), "/")
		if p == "" {
			p = "."
		}
		matches := p == "." || p == sub || strings.HasPrefix(sub, p+"/")
		if matches && (best == nil || len(p) > bestLen) {
			best = acl
			bestLen = len(p)
		}
	}
	return best
}

func (v *VirtualFS) resolveACL(col *config.Collection, base, sub string, user *User) (string, Permissions, bool) {
	acl := findACLForSub(col, sub)
	if acl == nil {
		if strings.Trim(path.Clean("/"+sub), "/") == "." {
			entries, err := os.ReadDir(base)
			if err != nil {
				return "", Permissions{}, false
			}
			for _, e := range entries {
				segACL := findACLForSub(col, e.Name())
				if segACL != nil && effectivePerms(segACL, user).Read {
					return base, Permissions{Read: true}, true
				}
			}
		}
		return "", Permissions{}, false
	}

	perms := effectivePerms(acl, user)
	if !perms.Read && !perms.Write {
		return "", Permissions{}, false
	}
	return filepath.Join(base, filepath.FromSlash(sub)), perms, true
}

type virtualRootFileInfo struct{}

func (virtualRootFileInfo) Name() string       { return "." }
func (virtualRootFileInfo) Size() int64        { return 0 }
func (virtualRootFileInfo) Mode() os.FileMode  { return os.ModeDir | 0555 }
func (virtualRootFileInfo) ModTime() time.Time { return time.Now() }
func (virtualRootFileInfo) IsDir() bool        { return true }
func (virtualRootFileInfo) Sys() interface{}   { return nil }

type collectionEntryFileInfo struct{ name string }

func (e collectionEntryFileInfo) Name() string       { return e.name }
func (e collectionEntryFileInfo) Size() int64        { return 0 }
func (e collectionEntryFileInfo) Mode() os.FileMode  { return os.ModeDir | 0555 }
func (e collectionEntryFileInfo) ModTime() time.Time { return time.Now() }
func (e collectionEntryFileInfo) IsDir() bool        { return true }
func (e collectionEntryFileInfo) Sys() interface{}   { return nil }

type virtualRootFile struct {
	collections []string
	readDirDone bool
}

func (f *virtualRootFile) Close() error                              { return nil }
func (f *virtualRootFile) Read([]byte) (int, error)                  { return 0, io.EOF }
func (f *virtualRootFile) Write([]byte) (int, error)                 { return 0, os.ErrPermission }
func (f *virtualRootFile) Stat() (os.FileInfo, error)                { return virtualRootFileInfo{}, nil }
func (f *virtualRootFile) Seek(int64, int) (int64, error)            { return 0, nil }
func (f *virtualRootFile) Readdir(int) ([]os.FileInfo, error) {
	if f.readDirDone {
		return nil, io.EOF
	}
	f.readDirDone = true
	infos := make([]os.FileInfo, 0, len(f.collections))
	for _, name := range f.collections {
		infos = append(infos, collectionEntryFileInfo{name: name})
	}
	return infos, nil
}

func (v *VirtualFS) rootCollections(ctx context.Context) []string {
	user := UserFromContext(ctx)
	if user == nil {
		return nil
	}

	tops := make([]string, 0, len(v.cfg.Collections))
	seen := make(map[string]bool)
	for i := range v.cfg.Collections {
		col := &v.cfg.Collections[i]
		top := strings.Trim(strings.TrimPrefix(col.Path, "/"), "/")
		if top == "" || seen[top] {
			continue
		}
		if v.userCanAccessCollection(col, user) {
			seen[top] = true
			tops = append(tops, top)
		}
	}
	return tops
}

func (v *VirtualFS) OpenFile(ctx context.Context, name string, flag int, perm os.FileMode) (webdav.File, error) {
	if strings.Trim(strings.Trim(path.Clean("/"+name), "/"), " ") == "" {
		tops := v.rootCollections(ctx)
		if tops == nil {
			return nil, os.ErrNotExist
		}
		return &virtualRootFile{collections: tops}, nil
	}

	realPath, perms, ok := v.resolve(ctx, name)
	if !ok {
		return nil, os.ErrNotExist
	}

	openRead := flag&os.O_WRONLY == 0
	openWrite := flag&(os.O_WRONLY|os.O_RDWR|os.O_CREATE|os.O_TRUNC|os.O_APPEND) != 0
	if openRead && !perms.Read {
		return nil, os.ErrPermission
	}
	if openWrite && !perms.Write {
		return nil, os.ErrPermission
	}
	if openWrite {
		if err := os.MkdirAll(filepath.Dir(realPath), 0755); err != nil {
			return nil, err
		}
	}

	rel := strings.TrimPrefix(filepath.ToSlash(realPath), "/")
	return webdav.Dir("/").OpenFile(ctx, rel, flag, perm)
}

func (v *VirtualFS) Stat(ctx context.Context, name string) (os.FileInfo, error) {
	if strings.Trim(path.Clean("/"+name), "/") == "" {
		if UserFromContext(ctx) == nil {
			return nil, os.ErrNotExist
		}
		return virtualRootFileInfo{}, nil
	}

	realPath, perms, ok := v.resolve(ctx, name)
	if !ok {
		return nil, os.ErrNotExist
	}
	if !perms.Read {
		return nil, os.ErrPermission
	}
	return os.Stat(realPath)
}

func (v *VirtualFS) Mkdir(ctx context.Context, name string, perm os.FileMode) error {
	realPath, perms, ok := v.resolve(ctx, name)
	if !ok {
		return os.ErrNotExist
	}
	if !perms.Write {
		return os.ErrPermission
	}
	return os.MkdirAll(realPath, perm)
}

func (v *VirtualFS) RemoveAll(ctx context.Context, name string) error {
	realPath, perms, ok := v.resolve(ctx, name)
	if !ok {
		return os.ErrNotExist
	}
	if !perms.Write {
		return os.ErrPermission
	}
	return os.RemoveAll(realPath)
}

func (v *VirtualFS) Rename(ctx context.Context, oldName, newName string) error {
	oldPath, oldPerms, okOld := v.resolve(ctx, oldName)
	newPath, newPerms, okNew := v.resolve(ctx, newName)
	if !okOld || !okNew {
		return os.ErrNotExist
	}
	if !oldPerms.Write || !newPerms.Write {
		return os.ErrPermission
	}
	return os.Rename(oldPath, newPath)
}

func passwordFromAuthHeader(r *http.Request) (username, password string, ok bool) {
	const prefix = "Basic "
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, prefix) {
		return "", "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(auth[len(prefix):]))
	if err != nil || len(decoded) == 0 {
		return "", "", false
	}
	cred := string(decoded)
	sep := strings.IndexByte(cred, ':')
	if sep < 0 {
		return cred, "", true
	}
	return cred[:sep], string(decoded[sep+1:]), true
}

func LoadIndexHTML(htmlPath string) []byte {
	if htmlPath != "" {
		if data, err := os.ReadFile(htmlPath); err == nil && len(data) > 0 {
			return data
		}
	}
	return nil
}

func IndexHandler(cfg *config.Config, indexHTML []byte, next http.Handler) http.Handler {
	collectionTops := map[string]bool{"": true}
	for _, col := range cfg.Collections {
		p := strings.Trim(strings.TrimPrefix(col.Path, "/"), "/")
		if p != "" {
			collectionTops[p] = true
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}

		trimmed := strings.Trim(r.URL.Path, "/")
		if strings.Contains(trimmed, "/") || !collectionTops[trimmed] {
			next.ServeHTTP(w, r)
			return
		}

		if len(indexHTML) == 0 {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodHead {
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(indexHTML)))
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(indexHTML)
	})
}

type authCache struct {
	mu    sync.RWMutex
	ttl   time.Duration
	entry map[string]cachedUser
}

type cachedUser struct {
	user   *User
	expiry time.Time
}

func newAuthCache(ttl time.Duration) *authCache {
	return &authCache{ttl: ttl, entry: make(map[string]cachedUser)}
}

func (c *authCache) key(username, password string) string {
	hash := sha256.Sum256([]byte(password))
	return username + ":" + hex.EncodeToString(hash[:])
}

func (c *authCache) get(key string) (*User, bool) {
	c.mu.RLock()
	cu, ok := c.entry[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(cu.expiry) {
		if ok {
			c.mu.Lock()
			delete(c.entry, key)
			c.mu.Unlock()
		}
		return nil, false
	}
	return cu.user, true
}

func (c *authCache) set(key string, u *User) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entry[key] = cachedUser{user: u, expiry: time.Now().Add(c.ttl)}
}

func Middleware(cfg *config.Config, next http.Handler) http.Handler {
	cache := newAuthCache(cfg.LDAP.AuthCacheTTL.ToDuration())
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		username, password, ok := passwordFromAuthHeader(r)
		if !ok || username == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if password == "" {
			w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV-please-re-enter-password"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		key := cache.key(username, password)
		if u, hit := cache.get(key); hit {
			next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
			return
		}

		ldapUser, err := ldapauth.Authenticate(&cfg.LDAP, username, password)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Basic realm="WebDAV-please-re-enter-password"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		u := &User{
			UID:        ldapUser.UID,
			Username:   ldapUser.Username,
			Mail:       ldapUser.Mail,
			CN:         ldapUser.CN,
			EmailLocal: ldapUser.EmailLocal,
			Groups:     ldapUser.Groups,
		}
		cache.set(key, u)
		next.ServeHTTP(w, r.WithContext(WithUser(r.Context(), u)))
	})
}
