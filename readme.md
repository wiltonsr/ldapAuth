# Traefik ldapAuth Middleware

This project is an in progress effort to create an open source middleware that enables authentication via LDAP in a similar way to [Traefik Enterprise](https://doc.traefik.io/traefik-enterprise/middlewares/ldap/).

## Caution

[Traefik](https://traefik.io) plugins are developed using the compiled [Go language](https://golang.org). Rather than being pre-compiled and linked, however, plugins are executed on the fly by [Yaegi](https://github.com/traefik/yaegi), an embedded Go interpreter.

Due to this Yaegi [issue](https://github.com/traefik/yaegi/issues/1275), the `ldap-go` module still does not work correctly. **Therefore this plugin is not ready for production**.

## Usage

```yml
whoami:
  image: "traefik/whoami"
  container_name: "simple-service"
  labels:
    - "traefik.enable=true"
    - "traefik.http.routers.whoami.rule=Host(`whoami.localhost`)"
    - "traefik.http.routers.whoami.entrypoints=web"
    # ldapAuth Register Middleware ====================================================
    - "traefik.http.routers.whoami.middlewares=ldap_auth"                             #
    # ldapAuth Option =================================================================
    - "traefik.http.middlewares.ldap_auth.plugin.ldapAuth.enabled=true"               #
    - "traefik.http.middlewares.ldap_auth.plugin.ldapAuth.debug=true"                 #
    - "traefik.http.middlewares.ldap_auth.plugin.ldapAuth.host=ldap.forumsys.com"     #
    - "traefik.http.middlewares.ldap_auth.plugin.ldapAuth.port=389"                   #
    - "traefik.http.middlewares.ldap_auth.plugin.ldapAuth.baseDn=dc=example,dc=com"   #
    - "traefik.http.middlewares.ldap_auth.plugin.ldapAuth.userUniqueId=uid"           #
    # =================================================================================
```

## Options

- `enabled` (Default: `true`) Controls whether requests will be checked against LDAP or not before being delivered.

- `debug` (Default: `false`) Enable debug mode to logs for detailed information about plugin operation.

- `host` (Default: `example.com`) LDAP server address where queries will be performed.

- `port` (Default: `389`) LDAP server port where queries will be performed.

- `baseDn` (Default: `dc=example,dc=org`) From where the plugin will search for users.

- `userUniqueId` (Default: `uid`) The unique identifier of users.
