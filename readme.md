<p align="center">
<img src="imgs/gandalpher.png" alt="Gandalpher" title="Gandalpher" />
</p>

<p align="center">
  <cite>
    "You shall authenticate to the LDAP to pass" - Gandalpher, the gopher
  </cite>
</p>

---

# Traefik ldapAuth Middleware

This project is an in progress effort to create an open source middleware that enables authentication via LDAP in a similar way to [Traefik Enterprise](https://doc.traefik.io/traefik-enterprise/middlewares/ldap/).

## Requirements

- Yaegi >= [v0.11.1](https://github.com/traefik/yaegi/releases/tag/v0.11.1)
- Traefik >= [v2.5.5](https://github.com/traefik/traefik/releases/tag/v2.5.5)
- go-ldap v3 >= [v3.1.4](https://github.com/go-ldap/ldap/releases/tag/v3.1.4)

[Traefik](https://traefik.io) plugins are developed using the compiled [Go language](https://golang.org). Rather than being pre-compiled and linked, however, plugins are executed on the fly by [Yaegi](https://github.com/traefik/yaegi), an embedded Go interpreter. Due to [traefik/yaegi#1275](https://github.com/traefik/yaegi/issues/1275), the `ldap-go` module only works after the listed version.

## Usage

### Add Plugin to Service

```yml
whoami:
  image: "traefik/whoami"
  container_name: "whoami"
  labels:
    - traefik.enable=true
    - traefik.http.routers.whoami.rule=Host(`whoami.localhost`)
    - traefik.http.routers.whoami.entrypoints=web
    # ldapAuth Register Middleware ====================================================
    - traefik.http.routers.whoami.middlewares=ldap_auth                               #
    # ldapAuth Options=================================================================
    - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.enabled=true                 #
    - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.logLevel=DEBUG               #
    - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.url=ldap://ldap.forumsys.com #
    - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.port=389                     #
    - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.baseDN=dc=example,dc=com     #
    - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.attribute=uid                #
    # =================================================================================
```

### Bind Mode Example

```yml
[...]
labels:
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.url=ldap://ldap.forumsys.com
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.port=389
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.baseDN=dc=example,dc=com
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.attribute=uid
```

### Search Mode Anonymous Example

```yml
[...]
labels:
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.url=ldap://ldap.forumsys.com
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.port=389
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.baseDN=dc=example,dc=com
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.attribute=uid
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.searchFilter=({{.Attribute}}={{.Username}})
```

### Search Mode Authenticated Example

```yml
[...]
labels:
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.url=ldap://ldap.forumsys.com
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.port=389
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.baseDN=dc=example,dc=com
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.attribute=uid
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.bindDN=uid=tesla,dc=example,dc=com
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.bindPassword=password
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.searchFilter=({{.Attribute}}={{.Username}})
```

### Advanced Search Mode Example

```yml
[...]
labels:
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.url=ldap://ldap.forumsys.com
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.port=389
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.baseDN=dc=example,dc=com
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.attribute=uid
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.bindDN=uid=tesla,dc=example,dc=com
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.bindPassword=password
  - traefik.http.middlewares.ldap_auth.plugin.ldapAuth.searchFilter=(&(objectClass=person)({{.Attribute}}={{.Username}}))
```

## Operations Mode

### Bind Mode

If no `searchFilter` is specified in its configuration, the middleware runs in the default bind mode, meaning it tries to make a simple bind request to the LDAP server with the credentials provided in the request headers. If the bind succeeds, the middleware forwards the request, otherwise it returns a 401 Unauthorized status code.

### Search Mode

If a `searchFilter` query is specified in the configuration, then the middleware runs in search mode. In this mode, a search query with the given filter is issued to the LDAP server before trying to bind. If `bindDN` and `bindPassword` have also been provided, then the search query will use this crentials. If result of this search returns only `1` record, it tries to issue a bind request with this record, otherwise it aborts a 401 Unauthorized status code.

## Options

##### `enabled`
*Optional, Default: `true`*

Controls whether requests will be checked against LDAP or not before being delivered.

##### `logLevel`
*Optional, Default: `INFO`*

Set `LogLevel` for detailed information about plugin operation.

##### `url`
*Required, Default: `""`*

LDAP server address where queries will be performed.

##### `port`
*Optional, Default: `389`*

LDAP server port where queries will be performed.

##### `attribute`
*Optional, Default: `cn`*

The attribute used to bind a user in [`Bind Mode`](#bind-mode). Bind queries use this pattern: `<attribute>=<username>,<baseDN>`, where the username is extracted from the request header.

##### `searchFilter`
*Optional, Default: `""`*

If not empty, the middleware will run in [`Search Mode`](#search-mode), filtering search results with the given query.

Filter queries can use the `{{.Option}}` format, from [text/template](https://pkg.go.dev/text/template#pkg-overview) go package, as placeholders that are replaced by the equivalent value from config. Additionaly, the username provided in the Authorization header of the request can also be used.

For example: `(&(objectClass=inetOrgPerson)(gidNumber=500)({{.Attribute}}={{.Username}}))`.

Will be replaced to: `(&(objectClass=inetOrgPerson)(gidNumber=500)(uid=tesla))`.

Note1: All filters options must be start with Uppercase to be replaced correctly.

Note2: `searchFilter` must escape curly braces when using [yml file](examples/dynamic-conf/ldapAuth-conf.yml).

Note3: `searchFilter` must escape curly braces when using [toml file](examples/dynamic-conf/ldapAuth-conf.toml).

##### `baseDN`
*Required, Default: `""`*

From where the plugin will search for users.

##### `bindDN`
*Optional, Default: `""`*

The domain name to bind to in order to authenticate to the LDAP server when running on [`Search Mode`](#search-mode). Leaving this empty with [`Search Mode`](#search-mode) means binds are anonymous, which is rarely expected behavior. It is not used when running in [`Bind Mode`](#bind-mode).

##### `bindPassword`
*Optional, Default: `""`*

The password corresponding to the `bindDN` specified when running in [`Search Mode`](#search-mode), used in order to authenticate to the LDAP server.

##### `forwardUsername`
*Optional, Default: `true`*

The `forwardUsername` option can be enabled to forward the username in a specific header, defined using the `forwardUsernameHeader` option.

##### `forwardUsernameHeader`
*Optional, Default: `Username`*

Name of the header to put the username in when forwarding it. This is not used if the `forwardUsername` option is set to `false`.

##### `forwardAuthorization`
*Optional, Default: `false`*

The `forwardAuthorization` option determines if the authorization header will be forwarded or stripped from the request after it has been approved by the middleware. `Attention`, enabling this option may expose the password of the LDAP user who is making the request.

##### `forwardExtraLDAPHeaders`
*Optional, Default: `false`*

The `forwardExtraLDAPHeaders` option determines if the LDAP Extra Headers, `Ldap-Extra-Attr-DN` and
`Ldap-Extra-Attr-CN`, will be added or not to request. This is not used if the `forwardUsername` option is set to `false` or if `searchFilter` is empty.

##### `wwwAuthenticateHeader`
*Optional, Default: `true`*

If the LDAP middleware receives a request with a missing or invalid Authorization header and `wwwAuthenticateHeader` is enabled, it will set a `WWW-Authenticate` header in the 401 Unauthorized response. See the [WWW-Authenticate header documentation](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/WWW-Authenticate) for more information.

##### `wwwAuthenticateHeaderRealm`
*Optional, Default: `""`*

The name of the realm to specify in the `WWW-Authenticate` header. This option is ineffective unless the `wwwAuthenticateHeader` option is set to true.
