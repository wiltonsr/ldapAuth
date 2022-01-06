// Package LdapAuth a ldap authentication plugin.
package ldapAuth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"reflect"

	"github.com/go-ldap/ldap/v3"
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
	UserUniqueID          string `json:"userUniqueID,omitempty" yaml:"userUniqueID,omitempty"`
	BaseDN                string `json:"baseDn,omitempty" yaml:"baseDn,omitempty"`
	BindDN                string `json:"bindDN,omitempty" yaml:"bindDN,omitempty"`
	BindPassword          string `json:"bindPassword,omitempty" yaml:"bindPassword,omitempty"`
	ForwardUsername       bool   `json:"forwardUsername,omitempty" yaml:"forwardUsername,omitempty"`
	ForwardUsernameHeader string `json:"forwardUsernameHeader,omitempty" yaml:"forwardUsernameHeader,omitempty"`
	ForwardAuthorization  bool   `json:"forwardAuthorization,omitempty" yaml:"forwardAuthorization,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Enabled:               true,
		Debug:                 false,
		Url:                   "",    // Supports: ldap://, ldaps://
		Port:                  389,   // Usually 389 or 636
		UserUniqueID:          "uid", // Usually uid or sAMAccountname
		BaseDN:                "",
		BindDN:                "",
		BindPassword:          "",
		ForwardUsername:       true,
		ForwardUsernameHeader: "Username",
		ForwardAuthorization:  false,
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
	log.Printf("Starting %s Middleware...", name)

	logConfig(config)

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
		RequireAuth(rw, req, err)
		return
	}

	conn, err := Connect(la.config.Url, la.config.Port)
	if err != nil {
		log.Printf(fmt.Sprintf("%s\n", err))
		RequireAuth(rw, req, err)
		return
	}

	isValidUser, err := ldapCheckUser(conn, la.config, user, password)

	defer conn.Close()

	if !isValidUser {
		log.Printf(fmt.Sprintf("%s\n", err))
		log.Printf("Authentication failed")
		RequireAuth(rw, req, err)
		return
	} else {
		log.Printf("Authentication succeeded")
	}

	// Sanitize Some Headers Infos
	if la.config.ForwardUsername {
		req.URL.User = url.User(user)
		req.Header[la.config.ForwardUsernameHeader] = []string{user}
	}

	/*
	 Prevent expose username and password on Header
	 if ForwardAuthorization option is set
	*/
	if !la.config.ForwardAuthorization {
		req.Header.Del("Authorization")
	}

	la.next.ServeHTTP(rw, req)
}

func ldapCheckUser(conn *ldap.Conn, config *Config, user, password string) (bool, error) {
	filter := fmt.Sprintf("(%s=%s)", config.UserUniqueID, user)
	result, err := BindUserSearch(conn, filter, config)

	// Return if search fails
	if err != nil {
		return false, err
	}

	userDN := result.Entries[0].DN
	log.Printf("Authenticating User: %s", userDN)

	// Bind User and password
	err = conn.Bind(userDN, password)
	return err == nil, err
}

func RequireAuth(w http.ResponseWriter, req *http.Request, err ...error) {
	w.Header().Set(contentType, "text/plan")
	w.Header().Set("WWW-Authenticate", `Basic realm="`+defaultRealm+`"`)
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte(fmt.Sprintf("%d %s\nError: %s\n", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), err)))
}

// Ldap Connection
func Connect(url string, port uint16) (*ldap.Conn, error) {
	conn, err := ldap.DialURL(fmt.Sprintf("%s:%d", url, port))
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func BindUserSearch(conn *ldap.Conn, filter string, config *Config) (*ldap.SearchResult, error) {
	if config.BindDN != "" && config.BindPassword != "" {
		log.Printf("Performing User BindDN Search")
		err := conn.Bind(config.BindDN, config.BindPassword)

		if err != nil {
			return nil, errors.New(fmt.Sprintf("BindDN Error: %s", err))
		}
	} else {
		log.Printf("Performing AnonymousBind Search")
		conn.UnauthenticatedBind("")
	}

	search := ldap.NewSearchRequest(
		config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{"dn"},
		nil,
	)

	result, err := conn.Search(search)

	if err != nil {
		log.Printf("Bind Search Error")
		return nil, err
	}

	if len(result.Entries) > 0 {
		return result, nil
	} else {
		return nil, errors.New("Couldn't fetch bind search entries")
	}
}

func logConfig(config *Config) {
	if config.Debug {
		/*
			Make this to prevent error msg
			"Error in Go routine: reflect: call of reflect.Value.NumField on ptr Value"
		*/
		var c Config
		c = *config

		v := reflect.ValueOf(c)
		typeOfS := v.Type()

		for i := 0; i < v.NumField(); i++ {
			log.Println(typeOfS.Field(i).Name, "=>", v.Field(i).Interface())
		}
	}
}
