// Package LdapAuth a ldap authentication plugin.
package ldapAuth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/go-ldap/ldap/v3"
	"github.com/wiltonsr/ldapAuth/ldaputils"
)

const (
	defaultRealm        = "traefik"
	authorizationHeader = "Authorization"
	contentType         = "Content-Type"
)

// Config the plugin configuration.
type Config struct {
	Enabled               bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Debug                 bool   `json:"debug,omitempty" yaml:"debug,omitempty"`
	Url                   string `json:"url,omitempty" yaml:"url,omitempty"`
	Port                  uint16 `json:"port,omitempty" yaml:"port,omitempty"`
	BindDN                string `json:"bindDN,omitempty" yaml:"bindDN,omitempty"`
	BindPassword          string `json:"bindPassword,omitempty" yaml:"bindPassword,omitempty"`
	BaseDN                string `json:"baseDn,omitempty" yaml:"baseDn,omitempty"`
	UserUniqueID          string `json:"userUniqueID,omitempty" yaml:"userUniqueID,omitempty"`
	ForwardUsername       bool   `json:"forwardUsername,omitempty" yaml:"forwardUsername,omitempty"`
	ForwardUsernameHeader string `json:"forwardUsernameHeader,omitempty" yaml:"forwardUsernameHeader,omitempty"`
	ForwardAuthorization  bool   `json:"forwardAuthorization,omitempty" yaml:"forwardAuthorization,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Enabled:               true,
		Debug:                 false,
		Url:                   "ldap://example.com", // Supports: ldap://, ldaps://, ldapi://
		Port:                  389,
		BindDN:                "",
		BindPassword:          "", // Usually 389 or 636
		BaseDN:                "dc=example,dc=org",
		UserUniqueID:          "uid", // Usually uid or sAMAccountname
		ForwardUsername:       true,
		ForwardUsernameHeader: "Username",
	}
}

// LdapAuth Struct plugin.
type LdapAuth struct {
	next   http.Handler
	name   string
	config *Config
}

// New created a new LdapAuth plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	log.Println("Starting", name, "Middleware...")
	if config.Debug {
		log.Println("Enabled       =>", config.Enabled)
		log.Println("Url          =>", config.Url)
		log.Println("Port          =>", config.Port)
		log.Println("BaseDN        =>", config.BaseDN)
		log.Println("UserUniqueID  =>", config.UserUniqueID)
	}

	return &LdapAuth{
		name:   name,
		next:   next,
		config: config,
	}, nil
}

func (la *LdapAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {

	if !la.config.Enabled {
		log.Printf("%s Disabled! Passing request...", la.name)
		la.next.ServeHTTP(rw, req)
		return
	}

	var err error
	user, password, ok := req.BasicAuth()

	if !ok {
		err = errors.New("no valid 'Authentication: Basic xxxx' header found in request")
		la.RequireAuth(rw, req, err)
		return
	}

	isValidUser, err := la.ldapCheckUser(user, password)

	if !isValidUser {
		log.Printf("Authentication failed")
		la.RequireAuth(rw, req, err)
		return
	} else {
		log.Printf("Authentication succeeded")
	}

	// Sanitize Some Headers Infos
	req.URL.User = url.User(user)
	req.Header["LDAP-User"] = []string{user}
	// Prevent expose username and password on Header
	req.Header.Del("Authorization")

	la.next.ServeHTTP(rw, req)
}

func (la *LdapAuth) ldapCheckUser(user, password string) (bool, error) {
	conn, err := ldaputils.Connect(la.config.Url, la.config.Port)
	if err != nil {
		log.Printf("Connection failed")
		return false, err
	} else {
		defer conn.Close()
		filter := fmt.Sprintf("(%s=%s)", la.config.UserUniqueID, user)
		log.Printf("Filter => %s\n", filter)
		attributes := []string{la.config.UserUniqueID}
		log.Printf("Attributes => %s\n", attributes)
		search := ldap.NewSearchRequest(la.config.BaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, attributes, nil)
		log.Printf("Search => %v\n", search)
		cur, err := conn.Search(search)
		if err != nil || len(cur.Entries) != 1 {
			err = errors.New("empty search")
			return false, err
		} else {
			err = conn.Bind(cur.Entries[0].DN, password)
			return err == nil, err
		}
	}
}

func (la *LdapAuth) RequireAuth(w http.ResponseWriter, req *http.Request, err ...error) {
	w.Header().Set(contentType, "text/plan")
	w.Header().Set("WWW-Authenticate", `Basic realm="`+defaultRealm+`"`)
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(fmt.Sprintf("%d %s\nError: %s", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), err)))
}
