# Traefik ldapAuth Middleware

This project is an in progress effort to create an open source middleware that enables authentication via LDAP in a similar way to [Traefik Enterprise](https://doc.traefik.io/traefik-enterprise/middlewares/ldap/).

## Requirements

- Yaegi [v0.11.1](https://github.com/traefik/yaegi/releases/tag/v0.11.1)
- Traefik [v2.5.5](https://github.com/traefik/traefik/releases/tag/v2.5.5)

[Traefik](https://traefik.io) plugins are developed using the compiled [Go language](https://golang.org). Rather than being pre-compiled and linked, however, plugins are executed on the fly by [Yaegi](https://github.com/traefik/yaegi), an embedded Go interpreter. Due to [traefik/yaegi#1275](https://github.com/traefik/yaegi/issues/1275), the `ldap-go` module only works after the listed version.

## Usage

```yml
whoami:
  image: "traefik/whoami"
  container_name: "simple-service"
  labels:
    - "traefik.enable=true"
    - "traefik.http.routers.whoami.rule=Host(`whoami.localhost`)"
    - "traefik.http.routers.whoami.entrypoints=web"
    # ldapAuth Register Middleware =======================================================
    - "traefik.http.routers.whoami.middlewares=ldap_auth"                                #
    # ldapAuth Options====================================================================
    - "traefik.http.middlewares.ldap_auth.plugin.ldapAuth.enabled=true"                  #
    - "traefik.http.middlewares.ldap_auth.plugin.ldapAuth.debug=true"                    #
    - "traefik.http.middlewares.ldap_auth.plugin.ldapAuth.url=ldap://ldap.forumsys.com" #
    - "traefik.http.middlewares.ldap_auth.plugin.ldapAuth.port=389"                      #
    - "traefik.http.middlewares.ldap_auth.plugin.ldapAuth.baseDN=dc=example,dc=com"      #
    - "traefik.http.middlewares.ldap_auth.plugin.ldapAuth.userUniqueID=uid"              #
    # ====================================================================================
```

## Options

##### `enabled`
*Optional, Default: `true`*

Controls whether requests will be checked against LDAP or not before being delivered.

##### `debug`
*Optional, Default: `false`*

Enable debug mode to logs for detailed information about plugin operation.

##### `url`
*Required, Default: `""`*

LDAP server address where queries will be performed.

##### `port`
*Optional, Default: `389`*

LDAP server port where queries will be performed.

##### `userUniqueId`
*Optional, Default: `uid`*

The unique identifier of users. This is used as a filter when performing bind in order to filter the user making the request.

##### `baseDN`
*Required, Default: `""`*

From where the plugin will search for users.

##### `BindDN`
*Optional, Default: `""`*

The domain name to bind to in order to authenticate to the LDAP server when search for `User DN`. Leaving this empty means binds are anonymous, which is rarely expected behavior.

##### `BindPassword`
*Optional, Default: `""`*

The password corresponding to the `bindDN` specified, used in order to authenticate to the LDAP server.

##### `ForwardUsername`
*Optional, Default: `true`*

The `forwardUsername` option can be enabled to forward the username in a specific header, defined using the `forwardUsernameHeader` option.

##### `ForwardUsernameHeader`
*Optional, Default: `Username`*

Name of the header to put the username in when forwarding it. This is not used if the `forwardUsername` option is set to `false`.

##### `ForwardAuthorization`
*Optional, Default: `false`*

The `forwardAuthorization` option determines if the authorization header will be forwarded or stripped from the request after it has been approved by the middleware. `Attention`, enabling this option may expose the password of the LDAP user who is making the request.
