// Package session to ldapAuth.
package session

import "time"

// Session contains the username of the user and the time at which it expires.
type Session struct {
	username string
	expiry   time.Time
}

// IsExpired determines if the Session has expired.
func (s Session) IsExpired() bool {
	return s.expiry.Before(time.Now())
}

// NewSession Struct plugin.
func NewSession(u string, t time.Time) Session {
	return Session{
		username: u,
		expiry:   t,
	}
}
