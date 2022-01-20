// Package ldapAuth a ldap authentication plugin.
//nolint
package ldapAuth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"strings"

	"github.com/go-ldap/ldap/v3"
)

//nolint
var (
	// LoggerDEBUG level.
	LoggerDEBUG = log.New(ioutil.Discard, "DEBUG: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile)
	// LoggerINFO level.
	LoggerINFO = log.New(ioutil.Discard, "INFO: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile)
	// LoggerERROR level.
	LoggerERROR = log.New(ioutil.Discard, "ERROR: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile)
)

// Config the plugin configuration.
type Config struct {
	Enabled                    bool   `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	LogLevel                   string `json:"logLevel,omitempty" yaml:"logLevel,omitempty"`
	URL                        string `json:"url,omitempty" yaml:"url,omitempty"`
	Port                       uint16 `json:"port,omitempty" yaml:"port,omitempty"`
	Attribute                  string `json:"attribute,omitempty" yaml:"attribute,omitempty"`
	SearchFilter               string `json:"searchFilter,omitempty" yaml:"searchFilter,omitempty"`
	BaseDN                     string `json:"baseDn,omitempty" yaml:"baseDn,omitempty"`
	BindDN                     string `json:"bindDn,omitempty" yaml:"bindDn,omitempty"`
	BindPassword               string `json:"bindPassword,omitempty" yaml:"bindPassword,omitempty"`
	ForwardUsername            bool   `json:"forwardUsername,omitempty" yaml:"forwardUsername,omitempty"`
	ForwardUsernameHeader      string `json:"forwardUsernameHeader,omitempty" yaml:"forwardUsernameHeader,omitempty"`
	ForwardAuthorization       bool   `json:"forwardAuthorization,omitempty" yaml:"forwardAuthorization,omitempty"`
	ForwardExtraLdapHeaders    bool   `json:"forwardExtraLdapHeaders,omitempty" yaml:"forwardExtraLdapHeaders,omitempty"`
	WWWAuthenticateHeader      bool   `json:"wwwAuthenticateHeader,omitempty" yaml:"wwwAuthenticateHeader,omitempty"`
	WWWAuthenticateHeaderRealm string `json:"wwwAuthenticateHeaderRealm,omitempty" yaml:"wwwAuthenticateHeaderRealm,omitempty"`
	Username                   string
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Enabled:                    true,
		LogLevel:                   "INFO",
		URL:                        "",   // Supports: ldap://, ldaps://
		Port:                       389,  // Usually 389 or 636
		Attribute:                  "cn", // Usually uid or sAMAccountname
		SearchFilter:               "",
		BaseDN:                     "",
		BindDN:                     "",
		BindPassword:               "",
		ForwardUsername:            true,
		ForwardUsernameHeader:      "Username",
		ForwardAuthorization:       false,
		ForwardExtraLdapHeaders:    false,
		WWWAuthenticateHeader:      true,
		WWWAuthenticateHeaderRealm: "",
		Username:                   "",
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
	SetLogger(config.LogLevel)

	LoggerINFO.Printf("Starting %s Middleware...", name)

	LogConfigParams(config)

	return &LdapAuth{
		name:   name,
		next:   next,
		config: config,
	}, nil
}

func (la *LdapAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	if !la.config.Enabled {
		LoggerINFO.Printf("%s Disabled! Passing request...", la.name)
		la.next.ServeHTTP(rw, req)
		return
	}

	var err error
	username, password, ok := req.BasicAuth()

	la.config.Username = username

	if !ok {
		err = errors.New("no valid 'Authentication: Basic xxxx' header found in request")
		RequireAuth(rw, req, la.config, err)
		return
	}

	conn, err := Connect(la.config.URL, la.config.Port)
	if err != nil {
		LoggerERROR.Printf("%s", err)
		RequireAuth(rw, req, la.config, err)
		return
	}

	isValidUser, entry, err := LdapCheckUser(conn, la.config, username, password)

	defer conn.Close()

	if !isValidUser {
		LoggerERROR.Printf("%s", err)
		LoggerERROR.Printf("Authentication failed")
		RequireAuth(rw, req, la.config, err)
		return
	}

	LoggerINFO.Printf("Authentication succeeded")

	// Sanitize Some Headers Infos
	if la.config.ForwardUsername {
		req.URL.User = url.User(username)
		req.Header[la.config.ForwardUsernameHeader] = []string{username}

		if la.config.ForwardExtraLdapHeaders && la.config.SearchFilter != "" {
			userDN := entry.DN
			userCN := entry.GetAttributeValue("cn")
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

// LdapCheckUser chec if user and password are correct.
func LdapCheckUser(conn *ldap.Conn, config *Config, username, password string) (bool, *ldap.Entry, error) {
	if config.SearchFilter == "" {
		LoggerDEBUG.Printf("Running in Bind Mode")
		userDN := fmt.Sprintf("%s=%s,%s", config.Attribute, username, config.BaseDN)
		LoggerDEBUG.Printf("Authenticating User: %s", userDN)
		err := conn.Bind(userDN, password)
		return err == nil, &ldap.Entry{}, err
	}

	LoggerDEBUG.Printf("Running in Search Mode")

	result, err := SearchMode(conn, config)
	// Return if search fails
	if err != nil {
		return false, &ldap.Entry{}, err
	}

	userDN := result.Entries[0].DN
	LoggerINFO.Printf("Authenticating User: %s", userDN)

	// Bind User and password
	err = conn.Bind(userDN, password)
	return err == nil, result.Entries[0], err
}

// RequireAuth set Auth request.
func RequireAuth(w http.ResponseWriter, req *http.Request, config *Config, err ...error) {
	w.Header().Set("Content-Type", "text/plan")
	if config.WWWAuthenticateHeader {
		wwwHeaderContent := "Basic"
		if config.WWWAuthenticateHeaderRealm != "" {
			wwwHeaderContent = fmt.Sprintf("Basic realm=\"%s\"", config.WWWAuthenticateHeaderRealm)
		}
		w.Header().Set("WWW-Authenticate", wwwHeaderContent)
	}
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(fmt.Sprintf("%d %s\nError: %s\n", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), err)))
}

// Connect return a LDAP Connection.
func Connect(url string, port uint16) (*ldap.Conn, error) {
	conn, err := ldap.DialURL(fmt.Sprintf("%s:%d", url, port))
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// SearchMode make search to LDAP and return results.
func SearchMode(conn *ldap.Conn, config *Config) (*ldap.SearchResult, error) {
	if config.BindDN != "" && config.BindPassword != "" {
		LoggerDEBUG.Printf("Performing User BindDN Search")
		err := conn.Bind(config.BindDN, config.BindPassword)
		if err != nil {
			return nil, fmt.Errorf("BindDN Error: %w", err)
		}
	} else {
		LoggerDEBUG.Printf("Performing AnonymousBind Search")
		_ = conn.UnauthenticatedBind("")
	}

	parsedSearchFilter, err := ParseSearchFilter(config)
	LoggerDEBUG.Printf("Search Filter: '%s'", parsedSearchFilter)

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
		LoggerERROR.Printf("Search Filter Error")
		return nil, err
	}

	switch {
	case len(result.Entries) == 1:
		return result, nil
	case len(result.Entries) < 1:
		return nil, fmt.Errorf("search silter return empty result")
	default:
		return nil, fmt.Errorf(fmt.Sprintf("search filter return multiple entries (%d)", len(result.Entries)))
	}
}

// ParseSearchFilter remove spaces and trailing from searchFilter.
func ParseSearchFilter(config *Config) (string, error) {
	filter := config.SearchFilter

	filter = strings.Trim(filter, "\n\t")
	filter = strings.TrimSpace(filter)
	filter = strings.ReplaceAll(filter, " ", "")
	filter = strings.Replace(filter, "\\", "", -1)

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

// SetLogger define global logger based in logLevel conf.
func SetLogger(level string) {
	switch level {
	case "ERROR":
		LoggerERROR.SetOutput(os.Stderr)
	case "INFO":
		LoggerERROR.SetOutput(os.Stderr)
		LoggerINFO.SetOutput(os.Stdout)
	case "DEBUG":
		LoggerERROR.SetOutput(os.Stderr)
		LoggerINFO.SetOutput(os.Stdout)
		LoggerDEBUG.SetOutput(os.Stdout)
	default:
		LoggerERROR.SetOutput(os.Stderr)
		LoggerINFO.SetOutput(os.Stdout)
	}
}

// LogConfigParams print confs when logLevel is DEBUG.
func LogConfigParams(config *Config) {
	/*
		Make this to prevent error msg
		"Error in Go routine: reflect: call of reflect.Value.NumField on ptr Value"
	*/
	c := *config

	v := reflect.ValueOf(c)
	typeOfS := v.Type()

	for i := 0; i < v.NumField(); i++ {
		LoggerDEBUG.Printf(fmt.Sprint(typeOfS.Field(i).Name, " => '", v.Field(i).Interface(), "'"))
	}
}
