package ldaputils

import (
	"errors"
	"fmt"

	"github.com/go-ldap/ldap/v3"
)

// Ldap Connection
func Connect(url string, port uint16) (*ldap.Conn, error) {
	// You can also use IP instead of FQDN
	conn, err := ldap.DialURL(fmt.Sprintf("%s:%d", url, port))
	if err != nil {
		return nil, err
	}

	return conn, nil
}

// Anonymous Bind and Search
func AnonymousBindAndSearch(conn *ldap.Conn, filter string) (*ldap.SearchResult, error) {
	conn.UnauthenticatedBind("")

	anonReq := ldap.NewSearchRequest(
		"",
		ldap.ScopeBaseObject, // you can also use ldap.ScopeWholeSubtree
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		filter,
		[]string{},
		nil,
	)
	result, err := conn.Search(anonReq)
	if err != nil {
		return nil, fmt.Errorf("Anonymous Bind Search Error: %s", err)
	}

	if len(result.Entries) > 0 {
		result.Entries[0].Print()
		return result, nil
	} else {
		return nil, errors.New("Couldn't fetch anonymous bind search entries")
	}
}
