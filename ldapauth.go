// Package ldapAuth a ldap authentication plugin.
// nolint
package ldapAuth

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/go-ldap/ldap/v3"
	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
)

const defaultCacheKey = "super-secret-key"

// nolint
var (
	store *sessions.CookieStore
	// LoggerDEBUG level.
	LoggerDEBUG = log.New(ioutil.Discard, "DEBUG: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile)
	// LoggerINFO level.
	LoggerINFO = log.New(ioutil.Discard, "INFO: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile)
	// LoggerWARNING level.
	LoggerWARNING = log.New(ioutil.Discard, "WARNING: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile)
	// LoggerERROR level.
	LoggerERROR = log.New(ioutil.Discard, "ERROR: ldapAuth: ", log.Ldate|log.Ltime|log.Lshortfile)
)

type LdapServerConfig struct {
	URL                  string `json:"url,omitempty" yaml:"url,omitempty"`
	Port                 uint16 `json:"port,omitempty" yaml:"port,omitempty"`
	Weight               uint16 `json:"weight,omitempty" yaml:"weight,omitempty"`
	StartTLS             bool   `json:"startTls,omitempty" yaml:"startTls,omitempty"`
	InsecureSkipVerify   bool   `json:"insecureSkipVerify,omitempty" yaml:"insecureSkipVerify,omitempty"`
	MinVersionTLS        string `json:"minVersionTls,omitempty" yaml:"minVersionTls,omitempty"`
	MaxVersionTLS        string `json:"maxVersionTls,omitempty" yaml:"maxVersionTls,omitempty"`
	CertificateAuthority string `json:"certificateAuthority,omitempty" yaml:"certificateAuthority,omitempty"`
}

// Config the plugin configuration.
type Config struct {
	Enabled                    bool               `json:"enabled,omitempty" yaml:"enabled,omitempty"`
	LogLevel                   string             `json:"logLevel,omitempty" yaml:"logLevel,omitempty"`
	ServerList                 []LdapServerConfig `json:"serverList,omitempty" yaml:"serverList,omitempty"`
	CacheTimeout               uint32             `json:"cacheTimeout,omitempty" yaml:"cacheTimeout,omitempty"`
	CacheCookieName            string             `json:"cacheCookieName,omitempty" yaml:"cacheCookieName,omitempty"`
	CacheCookiePath            string             `json:"cacheCookiePath,omitempty" yaml:"cacheCookiePath,omitempty"`
	CacheCookieSecure          bool               `json:"cacheCookieSecure,omitempty" yaml:"cacheCookieSecure,omitempty"`
	CacheKey                   string             `json:"cacheKey,omitempty" yaml:"cacheKey,omitempty"`
	CacheKeyLabel              string             `json:"cacheKeyLabel,omitempty" yaml:"cacheKeyLabel,omitempty"`
	Attribute                  string             `json:"attribute,omitempty" yaml:"attribute,omitempty"`
	SearchFilter               string             `json:"searchFilter,omitempty" yaml:"searchFilter,omitempty"`
	BaseDN                     string             `json:"baseDn,omitempty" yaml:"baseDn,omitempty"`
	BindDN                     string             `json:"bindDn,omitempty" yaml:"bindDn,omitempty"`
	BindPassword               string             `json:"bindPassword,omitempty" yaml:"bindPassword,omitempty"`
	BindPasswordLabel          string             `json:"bindPasswordLabel,omitempty" yaml:"bindPasswordLabel,omitempty"`
	ForwardUsername            bool               `json:"forwardUsername,omitempty" yaml:"forwardUsername,omitempty"`
	ForwardUsernameHeader      string             `json:"forwardUsernameHeader,omitempty" yaml:"forwardUsernameHeader,omitempty"`
	ForwardAuthorization       bool               `json:"forwardAuthorization,omitempty" yaml:"forwardAuthorization,omitempty"`
	ForwardExtraLdapHeaders    bool               `json:"forwardExtraLdapHeaders,omitempty" yaml:"forwardExtraLdapHeaders,omitempty"`
	WWWAuthenticateHeader      bool               `json:"wwwAuthenticateHeader,omitempty" yaml:"wwwAuthenticateHeader,omitempty"`
	WWWAuthenticateHeaderRealm string             `json:"wwwAuthenticateHeaderRealm,omitempty" yaml:"wwwAuthenticateHeaderRealm,omitempty"`
	EnableNestedGroupFilter    bool               `json:"enableNestedGroupsFilter,omitempty" yaml:"enableNestedGroupsFilter,omitempty"`
	AllowedGroups              []string           `json:"allowedGroups,omitempty" yaml:"allowedGroups,omitempty"`
	AllowedUsers               []string           `json:"allowedUsers,omitempty" yaml:"allowedUsers,omitempty"`
	Username                   string
	// params below are deprecated use 'ServerList' instead
	URL                  string `json:"url,omitempty" yaml:"url,omitempty"`
	Port                 uint16 `json:"port,omitempty" yaml:"port,omitempty"`
	StartTLS             bool   `json:"startTls,omitempty" yaml:"startTls,omitempty"`
	InsecureSkipVerify   bool   `json:"insecureSkipVerify,omitempty" yaml:"insecureSkipVerify,omitempty"`
	MinVersionTLS        string `json:"minVersionTls,omitempty" yaml:"minVersionTls,omitempty"`
	MaxVersionTLS        string `json:"maxVersionTls,omitempty" yaml:"maxVersionTls,omitempty"`
	CertificateAuthority string `json:"certificateAuthority,omitempty" yaml:"certificateAuthority,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Enabled:                    true,
		LogLevel:                   "INFO",
		ServerList:                 []LdapServerConfig{},
		CacheTimeout:               300, // In seconds, default to 5m
		CacheCookieName:            "ldapAuth_session_token",
		CacheCookiePath:            "",
		CacheCookieSecure:          false,
		CacheKey:                   defaultCacheKey,
		CacheKeyLabel:              "LDAP_AUTH_CACHE_KEY",
		Attribute:                  "cn", // Usually uid or sAMAccountname
		SearchFilter:               "",
		BaseDN:                     "",
		BindDN:                     "",
		BindPassword:               "",
		BindPasswordLabel:          "LDAP_AUTH_BIND_PASSWORD",
		ForwardUsername:            true,
		ForwardUsernameHeader:      "Username",
		ForwardAuthorization:       false,
		ForwardExtraLdapHeaders:    false,
		WWWAuthenticateHeader:      true,
		WWWAuthenticateHeaderRealm: "",
		EnableNestedGroupFilter:    false,
		AllowedGroups:              nil,
		AllowedUsers:               nil,
		Username:                   "",
		// deprecated use 'ServerList' instead
		URL: "",
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

	// It means the user is passing the URL directly
	if config.URL != "" {
		LoggerWARNING.Printf("Passing LDAP Server Attributes directly is deprecated, please use 'ServerList' instead")
		server := LdapServerConfig{
			URL:                  config.URL,
			Port:                 config.Port,
			Weight:               1,
			StartTLS:             config.StartTLS,
			InsecureSkipVerify:   config.InsecureSkipVerify,
			MinVersionTLS:        config.MinVersionTLS,
			MaxVersionTLS:        config.MaxVersionTLS,
			CertificateAuthority: config.CertificateAuthority,
		}

		config.ServerList = append(config.ServerList, server)
	}

	// Rank LDAP servers based on weight. Higher weight, higher precedence
	sort.Slice(config.ServerList, func(i, j int) bool {
		return config.ServerList[i].Weight > config.ServerList[j].Weight
	})

	settingDefaults(config)

	if config.BindDN != "" && config.BindPassword == "" {
		config.BindPassword = getSecret(config.BindPasswordLabel)
	}

	// if CacheKey is the default value we try to set it from secret
	if config.CacheKey == defaultCacheKey {
		cacheKey := getSecret(config.CacheKeyLabel)
		// we could not retrieve the secret, so we keep the default value
		if cacheKey != "" {
			config.CacheKey = cacheKey
		}
	}

	logConfigParams(config)

	// Create new session with CacheKey and CacheTimeout.
	var key []byte
	if config.CacheKey != "" {
		key = []byte(config.CacheKey)
	} else {
		key = securecookie.GenerateRandomKey(64)
		if key == nil {
			return nil, fmt.Errorf("Error generating random key")
		}
	}
	store = sessions.NewCookieStore(key)
	store.Options = &sessions.Options{
		HttpOnly: true,
		MaxAge:   int(config.CacheTimeout),
		Path:     config.CacheCookiePath,
		Secure:   config.CacheCookieSecure,
	}
	// This is called in sessions.NewCookieStore using the default MaxAge. If
	// it's not called again here, our CacheTimeout would affect only the
	// expiration time sent in the 'set-cookie' header but not the actual check
	// of the HMACed timestamp in the cookie, so a cookie would be accepted for
	// 30 days.
	store.MaxAge(store.Options.MaxAge)

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

	session, _ := store.Get(req, la.config.CacheCookieName)
	LoggerDEBUG.Printf("Session details: %v", session)

	username, password, ok := req.BasicAuth()
	username = strings.ToLower(username)

	la.config.Username = username

	if !ok {
		err = errors.New("no valid 'Authorization: Basic xxxx' header found in request")
		RequireAuth(rw, req, la.config, err)
		return
	}

	if auth, ok := session.Values["authenticated"].(bool); ok && auth {
		if session.Values["username"] == username {
			LoggerDEBUG.Printf("Session token Valid! Passing request...")
			ServeAuthenicated(la, session, rw, req)
			return
		}
		err = fmt.Errorf("session user: '%s' != Auth user: '%s'. Please, reauthenticate", session.Values["username"], username)
		// Invalidate session.
		session.Values["authenticated"] = false
		session.Values["username"] = username
		session.Options.MaxAge = -1
		session.Save(req, rw)
		RequireAuth(rw, req, la.config, err)
		return
	}

	LoggerDEBUG.Println("No session found! Trying to authenticate in LDAP")

	var conn *ldap.Conn = nil
	var serverInUse LdapServerConfig
	errStrings := []string{"All servers in ServerList are down"}

	for i, server := range la.config.ServerList {
		attempt := fmt.Sprintf("Attempt %d/%d", i+1, len(la.config.ServerList))
		LoggerDEBUG.Printf(attempt)

		if conn, err = Connect(server); err == nil {
			serverInUse = server
			break
		}

		LoggerERROR.Printf("%v", err)
		errStrings = append(errStrings, fmt.Sprintf("%s: %v", attempt, err))

		if i == len(la.config.ServerList)-1 {
			err = fmt.Errorf(strings.Join(errStrings, "\n"))
			RequireAuth(rw, req, la.config, err)
			return
		}
	}

	isValidUser, entry, err := LdapCheckUser(conn, la.config, serverInUse, username, password)

	if !isValidUser {
		defer conn.Close()
		LoggerERROR.Printf("%s", err)
		LoggerERROR.Printf("Authentication failed")
		RequireAuth(rw, req, la.config, err)
		return
	}

	isAuthorized, err := LdapCheckUserAuthorized(conn, la.config, entry, username)
	if !isAuthorized {
		defer conn.Close()
		LoggerERROR.Printf("%s", err)
		RequireAuth(rw, req, la.config, err)
		return
	}

	defer conn.Close()

	LoggerINFO.Printf("Authentication succeeded")

	// Set user as authenticated.
	session.Values["username"] = username
	session.Values["ldap-dn"] = entry.DN
	session.Values["ldap-cn"] = entry.GetAttributeValue("cn")
	session.Values["authenticated"] = true
	session.Save(req, rw)

	ServeAuthenicated(la, session, rw, req)
}

func ServeAuthenicated(la *LdapAuth, session *sessions.Session, rw http.ResponseWriter, req *http.Request) {
	// Sanitize Some Headers Infos.
	if la.config.ForwardUsername {
		username := session.Values["username"].(string)

		req.URL.User = url.User(username)
		req.Header[la.config.ForwardUsernameHeader] = []string{username}

		if la.config.ForwardExtraLdapHeaders && la.config.SearchFilter != "" {
			userDN := session.Values["ldap-dn"].(string)
			userCN := session.Values["ldap-cn"].(string)
			req.Header["Ldap-Extra-Attr-DN"] = []string{userDN}
			req.Header["Ldap-Extra-Attr-CN"] = []string{userCN}
		}
	}

	/*
	 Prevent expose username and password on Header
	 if ForwardAuthorization option is set.
	*/
	if !la.config.ForwardAuthorization {
		req.Header.Del("Authorization")
	}

	la.next.ServeHTTP(rw, req)
}

// LdapCheckUser check if user and password are correct.
func LdapCheckUser(conn *ldap.Conn, config *Config, server LdapServerConfig, username, password string) (bool, *ldap.Entry, error) {
	if config.SearchFilter == "" {
		LoggerDEBUG.Printf("Running in Bind Mode")
		userDN := fmt.Sprintf("%s=%s,%s", config.Attribute, username, config.BaseDN)
		userDN = strings.Trim(userDN, ",")
		LoggerDEBUG.Printf("Authenticating User: %s", userDN)
		err := conn.Bind(userDN, password)
		return err == nil, ldap.NewEntry(userDN, nil), err
	}

	LoggerDEBUG.Printf("Running in Search Mode")

	result, err := SearchMode(conn, config)
	// Return if search fails.
	if err != nil {
		return false, &ldap.Entry{}, err
	}

	userDN := result.Entries[0].DN
	LoggerINFO.Printf("Authenticating User: %s", userDN)

	// Create a new conn to validate user password. This prevents changing the bind made
	// previously, then LdapCheckUserAuthorized will use same operation mode
	_nconn, _ := Connect(server)
	defer _nconn.Close()

	// Bind User and password.
	err = _nconn.Bind(userDN, password)
	return err == nil, result.Entries[0], err
}

// LdapCheckUserAuthorized check if user is authorized post-authentication
func LdapCheckUserAuthorized(conn *ldap.Conn, config *Config, entry *ldap.Entry, username string) (bool, error) {
	// Check if authorization is required or simply authentication
	if len(config.AllowedUsers) == 0 && len(config.AllowedGroups) == 0 {
		LoggerDEBUG.Printf("No authorization requirements")
		return true, nil
	}

	// Check if user is explicitly allowed
	if LdapCheckAllowedUsers(conn, config, entry, username) {
		return true, nil
	}

	// Check if user is allowed through groups
	isValidGroups, err := LdapCheckUserGroups(conn, config, entry, username)
	if isValidGroups {
		return true, err
	}

	errMsg := fmt.Sprintf("User '%s' does not match any allowed users nor allowed groups.", username)

	if err != nil {
		err = fmt.Errorf("%w\n%s", err, errMsg)
	} else {
		err = errors.New(errMsg)
	}

	return false, err
}

// LdapCheckAllowedUsers check if user is explicitly allowed in AllowedUsers list
func LdapCheckAllowedUsers(conn *ldap.Conn, config *Config, entry *ldap.Entry, username string) bool {
	if len(config.AllowedUsers) == 0 {
		return false
	}

	found := false

	for _, u := range config.AllowedUsers {
		lowerAllowedUser := strings.ToLower(u)
		if lowerAllowedUser == username || lowerAllowedUser == strings.ToLower(entry.DN) {
			LoggerDEBUG.Printf("User: '%s' explicitly allowed in AllowedUsers", entry.DN)
			found = true
		}
	}

	return found
}

// LdapCheckUserGroups check if the is user is a member of any of the AllowedGroups list
func LdapCheckUserGroups(conn *ldap.Conn, config *Config, entry *ldap.Entry, username string) (bool, error) {

	if len(config.AllowedGroups) == 0 {
		return false, nil
	}

	found := false
	err := error(nil)
	var group_filter bytes.Buffer

	templ := "(|" +
		"(member={{.UserDN}})" +
		"(uniqueMember={{.UserDN}})" +
		"(memberUid={{.Username}})" +
		"{{if .EnableNestedGroupFilter}}" +
		"(member:1.2.840.113556.1.4.1941:={{.UserDN}})" +
		"{{end}}" +
		")"

	template.Must(template.New("group_filter_template").
		Parse(templ)).
		Execute(&group_filter, struct {
			UserDN                  string
			Username                string
			EnableNestedGroupFilter bool
		}{ldap.EscapeFilter(entry.DN), ldap.EscapeFilter(username), config.EnableNestedGroupFilter})

	LoggerDEBUG.Printf("Group Filter: '%s'", group_filter.String())

	res, err := conn.WhoAmI(nil)
	if err != nil {
		LoggerERROR.Printf("Failed to call WhoAmI(): %s", err)
	} else {
		LoggerDEBUG.Printf("Using credential: '%s' for Search Groups", res.AuthzID)
	}

	for _, g := range config.AllowedGroups {

		LoggerDEBUG.Printf("Searching Group: '%s' with User: '%s'", g, entry.DN)

		search := ldap.NewSearchRequest(
			g,
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			0,
			0,
			false,
			group_filter.String(),
			[]string{"member", "uniqueMember", "memberUid"},
			nil,
		)

		var result *ldap.SearchResult

		result, err = conn.Search(search)

		if err != nil {
			LoggerINFO.Printf("%s", err)
		}

		// Found one group that user belongs, break loop.
		if len(result.Entries) > 0 {
			LoggerDEBUG.Printf("User: '%s' found in Group: '%s'", entry.DN, g)
			found = true
			break
		}

		LoggerDEBUG.Printf("User: '%s' not found in Group: '%s'", username, g)
	}

	return found, err
}

// RequireAuth set Auth request.
func RequireAuth(w http.ResponseWriter, req *http.Request, config *Config, err error) {
	LoggerDEBUG.Println(err)
	w.Header().Set("Content-Type", "text/plain")
	if config.WWWAuthenticateHeader {
		wwwHeaderContent := "Basic"
		if config.WWWAuthenticateHeaderRealm != "" {
			wwwHeaderContent = fmt.Sprintf("Basic realm=\"%s\"", config.WWWAuthenticateHeaderRealm)
		}
		w.Header().Set("WWW-Authenticate", wwwHeaderContent)
	}

	w.WriteHeader(http.StatusUnauthorized)

	errMsg := strings.Trim(err.Error(), "\x00")
	_, _ = w.Write([]byte(fmt.Sprintf("%d %s\nError: %s\n", http.StatusUnauthorized, http.StatusText(http.StatusUnauthorized), errMsg)))
}

// Connect return a LDAP Connection.
func Connect(config LdapServerConfig) (*ldap.Conn, error) {
	var conn *ldap.Conn = nil
	var certPool *x509.CertPool
	var err error = nil

	if config.CertificateAuthority != "" {
		certPool = x509.NewCertPool()
		certPool.AppendCertsFromPEM([]byte(config.CertificateAuthority))
	}

	u, err := url.Parse(config.URL)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(u.Host)
	if err != nil {
		// we assume that error is due to missing port.
		host = u.Host
	}

	address := u.Scheme + "://" + net.JoinHostPort(host, strconv.FormatUint(uint64(config.Port), 10))
	LoggerDEBUG.Printf("Connect Address: '%s'", address)

	tlsCfg := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify,
		ServerName:         host,
		RootCAs:            certPool,
		MinVersion:         parseTlsVersion(config.MinVersionTLS),
		MaxVersion:         parseTlsVersion(config.MaxVersionTLS),
	}

	if u.Scheme == "ldap" && config.StartTLS {
		conn, err = ldap.DialURL(address)
		if err == nil {
			err = conn.StartTLS(tlsCfg)
		}
	} else if u.Scheme == "ldaps" {
		conn, err = ldap.DialURL(address, ldap.DialWithTLSConfig(tlsCfg))
	} else {
		conn, err = ldap.DialURL(address)
	}

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
		return nil, fmt.Errorf("search filter return empty result")
	default:
		return nil, fmt.Errorf(fmt.Sprintf("search filter return multiple entries (%d)", len(result.Entries)))
	}
}

// ParseSearchFilter remove spaces and trailing from searchFilter.
func ParseSearchFilter(config *Config) (string, error) {
	filter := config.SearchFilter

	filter = strings.Trim(filter, "\n\t")
	filter = strings.TrimSpace(filter)
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
	case "WARNING":
		LoggerERROR.SetOutput(os.Stderr)
		LoggerWARNING.SetOutput(os.Stderr)
	case "INFO":
		LoggerERROR.SetOutput(os.Stderr)
		LoggerWARNING.SetOutput(os.Stderr)
		LoggerINFO.SetOutput(os.Stdout)
	case "DEBUG":
		LoggerERROR.SetOutput(os.Stderr)
		LoggerWARNING.SetOutput(os.Stderr)
		LoggerINFO.SetOutput(os.Stdout)
		LoggerDEBUG.SetOutput(os.Stdout)
	default:
		LoggerERROR.SetOutput(os.Stderr)
		LoggerWARNING.SetOutput(os.Stderr)
		LoggerINFO.SetOutput(os.Stdout)
	}
}

func parseTlsVersion(version string) uint16 {
	switch version {
	case "tls.VersionTLS10", "VersionTLS10":
		return tls.VersionTLS10
	case "tls.VersionTLS11", "VersionTLS11":
		return tls.VersionTLS11
	case "tls.VersionTLS12", "VersionTLS12":
		return tls.VersionTLS12
	case "tls.VersionTLS13", "VersionTLS13":
		return tls.VersionTLS13
	default:
		LoggerWARNING.Printf("Version: '%s' doesnt match any value. Using 'tls.VersionTLS10' instead", version)
		LoggerWARNING.Printf("Please check https://pkg.go.dev/crypto/tls#pkg-constants to a list of valid versions")
		return tls.VersionTLS10
	}
}

// logConfigParams print confs when logLevel is DEBUG.
func logConfigParams(v interface{}) {
	val := reflect.ValueOf(v)
	printFieldsRecursive(val, "")
}

// logConfigParams recursively print parameters value.
func printFieldsRecursive(val reflect.Value, indent string) {
	val = reflect.Indirect(val)
	if val.Kind() == reflect.Struct {
		for i := 0; i < val.NumField(); i++ {
			field := val.Type().Field(i)
			fieldValue := val.Field(i)

			if fieldValue.Kind() == reflect.Struct {
				LoggerDEBUG.Printf("%s%s:\n", indent, field.Name)
				printFieldsRecursive(fieldValue, indent+"  ")
			} else if fieldValue.Kind() == reflect.Slice {
				LoggerDEBUG.Printf("%s%s:\n", indent, field.Name)
				for j := 0; j < fieldValue.Len(); j++ {
					printFieldsRecursive(fieldValue.Index(j), indent+"  ")
				}
				if fieldValue.Len() == 0 {
					LoggerDEBUG.Printf("%s'[]'\n", indent+"  ")
				}
			} else {
				LoggerDEBUG.Printf("%s%s: '%v'\n", indent, field.Name, fieldValue)
			}
		}
	} else {
		LoggerDEBUG.Printf("%s'%v'\n", indent, val.Interface())
	}
}

// settingDefaults to serverList parameters no explicit passed by the user
func settingDefaults(config *Config) {
	for i, server := range config.ServerList {
		// Default MinVersionTLS value
		if server.MinVersionTLS == "" {
			config.ServerList[i].MinVersionTLS = "tls.VersionTLS12"
		}

		// Default MaxVersionTLS value
		if server.MaxVersionTLS == "" {
			config.ServerList[i].MaxVersionTLS = "tls.VersionTLS13"
		}

		// Default Port value
		if server.Port == 0 {
			config.ServerList[i].Port = 389
		}
	}
}

// retrieve a secret value from environment variable or secret on the FS
func getSecret(label string) string {
	secret := os.Getenv(strings.ToUpper(label))

	if secret != "" {
		return secret
	}

	path := fmt.Sprintf("/run/secrets/%s", strings.ToLower(label))

	if os.Getenv(strings.ToUpper(label)+"_FILE") != "" {
		path = os.Getenv(strings.ToUpper(label) + "_FILE")
	}

	b, err := os.ReadFile(path)
	if err != nil {
		LoggerWARNING.Printf("could not load secret %s: %s", label, err)
		return ""
	}
	return strings.TrimSpace(string(b))
}
