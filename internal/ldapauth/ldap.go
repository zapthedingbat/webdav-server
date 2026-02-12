package ldapauth

import (
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/zapthedingbat/webdav-server/internal/config"
)

// User holds the authenticated user's identity and group memberships.
// Values are used for placeholder substitution in fs_path: %uid%, %username%, %mail%, %cn%, %email_local%
type User struct {
	UID        string   // %uid% - primary identifier
	Username   string   // %username%
	Mail       string   // %mail%
	CN         string   // %cn% - common name
	EmailLocal string   // %email_local% - part before @ of mail
	Groups     []string // LDAP group DNs
}

// Authenticate verifies username/password against LDAP and returns the user's UID and groups.
func Authenticate(cfg *config.LDAP, username, password string) (*User, error) {
	conn, err := ldap.DialURL(cfg.URL)
	if err != nil {
		return nil, fmt.Errorf("ldap connect: %w", err)
	}
	defer conn.Close()

	if strings.HasPrefix(cfg.URL, "ldaps://") {
		if err := conn.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			return nil, fmt.Errorf("ldap starttls: %w", err)
		}
	}

	if err := conn.Bind(cfg.BindDN, cfg.BindPassword); err != nil {
		return nil, fmt.Errorf("ldap bind: %w", err)
	}

	searchReq := ldap.NewSearchRequest(
		cfg.BaseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		fmt.Sprintf("(&%s(%s=%s))", cfg.UserFilter, cfg.UsernameAttribute, ldap.EscapeFilter(username)),
		[]string{cfg.UsernameAttribute, "uid", "mail", "cn", "username", cfg.GroupAttribute},
		nil,
	)
	result, err := conn.Search(searchReq)
	if err != nil {
		return nil, fmt.Errorf("ldap search: %w", err)
	}
	if len(result.Entries) == 0 {
		return nil, fmt.Errorf("user not found")
	}
	if len(result.Entries) > 1 {
		return nil, fmt.Errorf("multiple users matched")
	}
	entry := result.Entries[0]
	userDN := entry.DN

	if err := conn.Bind(userDN, password); err != nil {
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	uid := entry.GetAttributeValue("uid")
	if uid == "" {
		uid = entry.GetAttributeValue(cfg.UsernameAttribute)
	}
	if uid == "" {
		uid = username
	}

	// Values for fs_path placeholder substitution: %uid% %username% %mail% %cn% %email_local%
	userName := entry.GetAttributeValue("username")
	if userName == "" {
		userName = entry.GetAttributeValue("cn")
	}
	mail := entry.GetAttributeValue("mail")
	cn := entry.GetAttributeValue("cn")
	emailLocal := ""
	if mail != "" {
		if parts := strings.SplitN(mail, "@", 2); len(parts) > 0 && parts[0] != "" {
			emailLocal = parts[0]
		}
	}

	groups := entry.GetAttributeValues(cfg.GroupAttribute)
	if groups == nil {
		groups = []string{}
	}

	return &User{UID: uid, Username: userName, Mail: mail, CN: cn, EmailLocal: emailLocal, Groups: groups}, nil
}
