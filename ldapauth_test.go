// Package ldapAuth_test a test suit for ldap authentication plugin.
// nolint
package ldapAuth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"
)

func TestDemo(t *testing.T) {
	cfg := CreateConfig()

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := New(ctx, next, cfg, "ldapAuth")
	if err != nil {
		t.Fatal(err)
	}

	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	handler.ServeHTTP(recorder, req)

}

func TestGetSecret(t *testing.T) {

	t.Setenv("LDAP_AUTH_BIND_PASSWORD", "verysecret")

	secret := getSecret("LDAP_AUTH_BIND_PASSWORD")
	if secret != "verysecret" {
		t.Fatal("secret should be loaded from env")
	}

	secret = getSecret("LDAP_AUTH_BIND_PASSWORD_NOT_SET")
	if secret != "" {
		t.Fatal("secret should be empty")
	}

	if runtime.GOOS == "windows" {
		t.Setenv("LDAP_AUTH_CACHE_KEY_FILE", ".\\mock\\secret")
	} else {
		t.Setenv("LDAP_AUTH_CACHE_KEY_FILE", "./mock/secret")
	}

	secret = getSecret("LDAP_AUTH_CACHE_KEY")

	if secret != "this_is_a_secret" {
		t.Fatal("secret should be loaded from file")
	}

	t.Setenv("ANOTHER_SECRET_FILE", "./mock/secret")
	t.Setenv("ANOTHER_SECRET", "this_is_another_secret")

	secret = getSecret("ANOTHER_SECRET")
	if secret != "this_is_another_secret" {
		t.Fatal("secret should be loaded from env and not from file")
	}
}
