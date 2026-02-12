package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration (YAML-driven).
type Config struct {
	Server      Server       `yaml:"server"`
	LDAP        LDAP         `yaml:"ldap"`
	Collections []Collection `yaml:"collections"`
}

type Server struct {
	Listen string `yaml:"listen"`
}

// Duration is time.Duration with YAML unmarshaling from a duration string (e.g. "5m").
type Duration time.Duration

func (d *Duration) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v interface{}
	if err := unmarshal(&v); err != nil {
		return err
	}
	x, ok := v.(string)
	if !ok {
		return fmt.Errorf("auth_cache_ttl must be a duration string (e.g. 5m)")
	}
	parsed, err := time.ParseDuration(x)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) ToDuration() time.Duration { return time.Duration(d) }

type LDAP struct {
	URL               string   `yaml:"url"`
	BaseDN            string   `yaml:"base_dn"`
	BindDN            string   `yaml:"bind_dn"`
	BindPassword      string   `yaml:"bind_password"`
	UserFilter        string   `yaml:"user_filter"`
	UsernameAttribute string   `yaml:"username_attribute"`
	GroupAttribute    string   `yaml:"group_attribute"`
	AuthCacheTTL      Duration `yaml:"auth_cache_ttl"`
}

// Collection defines one WebDAV collection (path) and who can access it.
type Collection struct {
	Path   string          `yaml:"path"`    // URL path, e.g. /home or /shared
	FSPath string          `yaml:"fs_path"` // filesystem root; use placeholders when home is true
	Home   bool            `yaml:"home"`    // if true: /home maps to fs_path expanded with user placeholders
	ACLs   []CollectionACL `yaml:"acls"`    // path-based rules; required when home is false
}

// CollectionACL applies to one path within a collection. Longest matching path wins. Access checked on open/stat/write; listings show real dir.
type CollectionACL struct {
	Path  string    `yaml:"path"`  // e.g. "shared", "shared/team", or "." for whole collection
	Rules []ACLRule `yaml:"rules"` // ordered list of user/group rules
}

// ACLRule assigns one mode to a user or group. Mode: "r" (read), "w" (write, including delete), or "rw".
type ACLRule struct {
	Principle string `yaml:"principle"` // "user:sam" or "group:cn=admins,dc=example,dc=com"
	Mode      string `yaml:"mode"`      // "r", "w", or "rw"
}

// Load reads config from a YAML file and applies environment variable overrides.
// The app never writes to the config path; use the image entrypoint to copy a default only if the file is missing.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	return unmarshalAndApplyDefaults(data)
}

func unmarshalAndApplyDefaults(data []byte) (*Config, error) {
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if c.Server.Listen == "" {
		c.Server.Listen = ":8080"
	}
	if c.LDAP.UsernameAttribute == "" {
		c.LDAP.UsernameAttribute = "uid"
	}
	if c.LDAP.GroupAttribute == "" {
		c.LDAP.GroupAttribute = "memberOf"
	}
	if c.LDAP.UserFilter == "" {
		c.LDAP.UserFilter = "(objectClass=person)"
	}
	if c.LDAP.AuthCacheTTL.ToDuration() <= 0 {
		c.LDAP.AuthCacheTTL = Duration(5 * time.Minute)
	}
	if v := os.Getenv("LDAP_URL"); v != "" {
		c.LDAP.URL = v
	}
	if v := os.Getenv("LDAP_BASE_DN"); v != "" {
		c.LDAP.BaseDN = v
	}
	if v := os.Getenv("LDAP_BIND_DN"); v != "" {
		c.LDAP.BindDN = v
	}
	if v := os.Getenv("LDAP_BIND_PASSWORD"); v != "" {
		c.LDAP.BindPassword = v
	}
	if v := os.Getenv("LDAP_USER_FILTER"); v != "" {
		c.LDAP.UserFilter = v
	}
	if v := os.Getenv("LDAP_USERNAME_ATTRIBUTE"); v != "" {
		c.LDAP.UsernameAttribute = v
	}
	if v := os.Getenv("LDAP_GROUP_ATTRIBUTE"); v != "" {
		c.LDAP.GroupAttribute = v
	}
	return &c, nil
}
