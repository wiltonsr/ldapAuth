// Package LdapAuth a ldap authentication plugin.
package ldapAuth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"reflect"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

const (
	defaultRealm        = "traefik"
	authorizationHeader = "Authorization"
	contentType         = "Content-Type"
)

// Config the plugin configuration.
type Config struct {
	Enabled                 bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	Debug                   bool   `json:"debug,omitempty" yaml:"debug,omitempty"`
	Url                     string `json:"url,omitempty" yaml:"url,omitempty"`
	Port                    uint16 `json:"port,omitempty" yaml:"port,omitempty"`
	Attribute               string `json:"attribute,omitempty" yaml:"attribute,omitempty"`
	SearchFilter            string `json:"searchFilter,omitempty" yaml:"searchFilter,omitempty"`
	BaseDN                  string `json:"baseDn,omitempty" yaml:"baseDn,omitempty"`
	BindDN                  string `json:"bindDN,omitempty" yaml:"bindDN,omitempty"`
	BindPassword            string `json:"bindPassword,omitempty" yaml:"bindPassword,omitempty"`
	ForwardUsername         bool   `json:"forwardUsername,omitempty" yaml:"forwardUsername,omitempty"`
	ForwardUsernameHeader   string `json:"forwardUsernameHeader,omitempty" yaml:"forwardUsernameHeader,omitempty"`
	ForwardAuthorization    bool   `json:"forwardAuthorization,omitempty" yaml:"forwardAuthorization,omitempty"`
	ForwardExtraLDAPHeaders bool   `json:"forwardExtraLDAPHeaders,omitempty" yaml:"forwardExtraLDAPHeaders,omitempty"`
	Username                string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Enabled:                 true,
		Debug:                   false,
		Url:                     "",   // Supports: ldap://, ldaps://
		Port:                    389,  // Usually 389 or 636
		Attribute:               "cn", // Usually uid or sAMAccountname
		SearchFilter:            "",
		BaseDN:                  "",
		BindDN:                  "",
		BindPassword:            "",
		ForwardUsername:         true,
		ForwardUsernameHeader:   "Username",
		ForwardAuthorization:    false,
		ForwardExtraLDAPHeaders: false,
		Username:                "",
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

	LogConfig(config)

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
	username, password, ok := req.BasicAuth()

	la.config.Username = username

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

	isValidUser, entry, err := LdapCheckUser(conn, la.config, username, password)

	defer conn.Close()

	if !isValidUser {
		log.Printf(fmt.Sprintf("%s\n", err))
		log.Printf("Authentication failed")
		RequireAuth(rw, req, err)
		return
	} else {
		log.Printf("Authentication succeeded")
	}

	userDN := entry.DN
	userCN := entry.GetAttributeValue("cn")

	// Sanitize Some Headers Infos
	if la.config.ForwardUsername {
		req.URL.User = url.User(username)
		req.Header[la.config.ForwardUsernameHeader] = []string{username}

		if la.config.ForwardExtraLDAPHeaders {
			req.Header["Ldap-Extra-Attr-DN"] = []string{userDN}
			req.Header["Ldap-Extra-Attr-CN"] = []string{userCN}
		}
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

func LdapCheckUser(conn *ldap.Conn, config *Config, username, password string) (bool, *ldap.Entry, error) {
	if config.SearchFilter == "" {
		log.Printf("Running in Bind Mode")
		userDN := fmt.Sprintf("%s=%s,%s", config.Attribute, username, config.BaseDN)
		log.Printf("Authenticating User: %s", userDN)
		err := conn.Bind(userDN, password)
		return err == nil, &ldap.Entry{}, err
	} else {
		log.Printf("Running in Search Mode")

		result, err := SearchMode(conn, config, username)

		// Return if search fails
		if err != nil {
			return false, &ldap.Entry{}, err
		}

		userDN := result.Entries[0].DN
		log.Printf("Authenticating User: %s", userDN)

		// Bind User and password
		err = conn.Bind(userDN, password)
		return err == nil, result.Entries[0], err
	}
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

func SearchMode(conn *ldap.Conn, config *Config, username string) (*ldap.SearchResult, error) {
	if config.BindDN != "" && config.BindPassword != "" {
		log.Printf("Performing User BindDN Search")
		err := conn.Bind(config.BindDN, config.BindPassword)

		if err != nil {
			return nil, fmt.Errorf("BindDN Error: %s", err)
		}
	} else {
		log.Printf("Performing AnonymousBind Search")
		conn.UnauthenticatedBind("")
	}

	parsedSearchFilter, err := ParseSearchFilter(config)
	log.Printf("Search Filter: '%s'", parsedSearchFilter)

	if err != nil {
		return nil, err
	}

	search := ldap.NewSearchRequest(
		config.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		parsedSearchFilter,
		[]string{"dn", "cn"},
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
		return nil, errors.New("couldn't fetch bind search entries")
	}
}

func ParseSearchFilter(config *Config) (string, error) {
	filter := config.SearchFilter

	filter = strings.Trim(filter, "\n\t")
	filter = strings.TrimSpace(filter)
	filter = strings.ReplaceAll(filter, " ", "")

	tmpl, err := template.New("search_template").Parse(filter)

	if err != nil {
		return "", err
	}

	var out bytes.Buffer

	err = tmpl.Execute(&out, config)

	if err != nil {
		return "", err
	}

	return out.String(), nil
}

func LogConfig(config *Config) {
	if config.Debug {
		/*
			Make this to prevent error msg
			"Error in Go routine: reflect: call of reflect.Value.NumField on ptr Value"
		*/
		var c Config = *config

		v := reflect.ValueOf(c)
		typeOfS := v.Type()

		for i := 0; i < v.NumField(); i++ {
			log.Println(typeOfS.Field(i).Name, "=>", v.Field(i).Interface())
		}
	}
}
