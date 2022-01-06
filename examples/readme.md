# Traefik ldapAuth Examples

We use [Forumsys LDAP Test Server](https://www.forumsys.com/tutorials/integration-how-to/ldap/online-ldap-test-server/) to validate the plugin's operation.

We could perform a Anonymous Bind:

```bash
$ ldapsearch -x -b "dc=example,dc=com" -H ldap://ldap.forumsys.com
```

Or Authenticated Bind:

```bash
$ ldapsearch -x -b "dc=example,dc=com" -H ldap://ldap.forumsys.com -D "uid=tesla,dc=example,dc=com" -w password
```

And the Output will be like this:

<details>
 <summary>Forumsys LDAP Result</summary>

```text

# extended LDIF
#
# LDAPv3
# base <dc=example,dc=com> with scope subtree
# filter: (objectclass=*)
# requesting: ALL
#

# example.com
dn: dc=example,dc=com
objectClass: top
objectClass: dcObject
objectClass: organization
o: example.com
dc: example

# admin, example.com
dn: cn=admin,dc=example,dc=com
objectClass: simpleSecurityObject
objectClass: organizationalRole
cn: admin
description: LDAP administrator

# newton, example.com
dn: uid=newton,dc=example,dc=com
sn: Newton
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: newton
mail: newton@ldap.forumsys.com
cn: Isaac Newton

# einstein, example.com
dn: uid=einstein,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: Albert Einstein
sn: Einstein
uid: einstein
mail: einstein@ldap.forumsys.com
telephoneNumber: 314-159-2653

# tesla, example.com
dn: uid=tesla,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
objectClass: posixAccount
cn: Nikola Tesla
sn: Tesla
uid: tesla
mail: tesla@ldap.forumsys.com
uidNumber: 88888
gidNumber: 99999
homeDirectory: home

# galieleo, example.com
dn: uid=galieleo,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: Galileo Galilei
sn: Galilei
uid: galieleo
mail: galieleo@ldap.forumsys.com

# euler, example.com
dn: uid=euler,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
uid: euler
sn: Euler
cn: Leonhard Euler
mail: euler@ldap.forumsys.com

# gauss, example.com
dn: uid=gauss,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: Carl Friedrich Gauss
sn: Gauss
uid: gauss
mail: gauss@ldap.forumsys.com

# riemann, example.com
dn: uid=riemann,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: Bernhard Riemann
sn: Riemann
uid: riemann
mail: riemann@ldap.forumsys.com

# euclid, example.com
dn: uid=euclid,dc=example,dc=com
uid: euclid
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: Euclid
sn: Euclid
mail: euclid@ldap.forumsys.com

# mathematicians, example.com
dn: ou=mathematicians,dc=example,dc=com
uniqueMember: uid=euclid,dc=example,dc=com
uniqueMember: uid=riemann,dc=example,dc=com
uniqueMember: uid=euler,dc=example,dc=com
uniqueMember: uid=gauss,dc=example,dc=com
uniqueMember: uid=test,dc=example,dc=com
ou: mathematicians
cn: Mathematicians
objectClass: groupOfUniqueNames
objectClass: top

# scientists, example.com
dn: ou=scientists,dc=example,dc=com
uniqueMember: uid=einstein,dc=example,dc=com
uniqueMember: uid=galieleo,dc=example,dc=com
uniqueMember: uid=tesla,dc=example,dc=com
uniqueMember: uid=newton,dc=example,dc=com
uniqueMember: uid=training,dc=example,dc=com
uniqueMember: uid=jmacy,dc=example,dc=com
ou: scientists
cn: Scientists
objectClass: groupOfUniqueNames
objectClass: top

# read-only-admin, example.com
dn: cn=read-only-admin,dc=example,dc=com
sn: Read Only Admin
cn: read-only-admin
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top

# italians, scientists, example.com
dn: ou=italians,ou=scientists,dc=example,dc=com
uniqueMember: uid=tesla,dc=example,dc=com
ou: italians
cn: Italians
objectClass: groupOfUniqueNames
objectClass: top

# test, example.com
dn: uid=test,dc=example,dc=com
objectClass: posixAccount
objectClass: top
objectClass: inetOrgPerson
gidNumber: 0
givenName: Test
sn: Test
displayName: Test
uid: test
initials: TS
homeDirectory: home
cn: Test
uidNumber: 24601
o: Company

# chemists, example.com
dn: ou=chemists,dc=example,dc=com
ou: chemists
objectClass: groupOfUniqueNames
objectClass: top
uniqueMember: uid=curie,dc=example,dc=com
uniqueMember: uid=boyle,dc=example,dc=com
uniqueMember: uid=nobel,dc=example,dc=com
uniqueMember: uid=pasteur,dc=example,dc=com
cn: Chemists

# curie, example.com
dn: uid=curie,dc=example,dc=com
uid: curie
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: Marie Curie
sn: Curie
mail: curie@ldap.forumsys.com

# nobel, example.com
dn: uid=nobel,dc=example,dc=com
uid: nobel
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
mail: nobel@ldap.forumsys.com
sn: Nobel
cn: Alfred Nobel

# boyle, example.com
dn: uid=boyle,dc=example,dc=com
uid: boyle
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: Robert Boyle
sn: Boyle
mail: boyle@ldap.forumsys.com
telephoneNumber: 999-867-5309

# pasteur, example.com
dn: uid=pasteur,dc=example,dc=com
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
sn: Pasteur
cn: Louis Pasteur
uid: pasteur
telephoneNumber: 602-214-4978
mail: pasteur@ldap.forumsys.com

# nogroup, example.com
dn: uid=nogroup,dc=example,dc=com
uid: nogroup
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: No Group
mail: nogroup@ldap.forumsys.com
sn: Group

# training, example.com
dn: uid=training,dc=example,dc=com
uid: training
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
cn: FS Training
sn: training
mail: training@forumsys.com
telephoneNumber: 888-111-2222

# jmacy, example.com
dn: uid=jmacy,dc=example,dc=com
uid: jmacy
telephoneNumber: 888-111-2222
sn: training
cn: FS Training
objectClass: inetOrgPerson
objectClass: organizationalPerson
objectClass: person
objectClass: top
mail: jmacy-training@forumsys.com

# search result
search: 2
result: 0 Success

# numResponses: 24
# numEntries: 23
```
</details><br>

You can run the examples with the following command
```bash
$ docker-compose -f examples/docker-compose-only.yml up

or

$ docker-compose -f examples/docker-compose-dynamic-conf.yml up
```

After this, its possible to test using `curl`:
```bash
curl --user tesla:password -H "Host: whoami.localhost" http://0.0.0.0
```

You should see something like this:
```text
Hostname: 507ac918ddd8
IP: 127.0.0.1
IP: 172.20.0.2
RemoteAddr: 172.20.0.3:36198
GET / HTTP/1.1
Host: whoami.localhost
User-Agent: curl/7.80.0
Accept: */*
Accept-Encoding: gzip
Username: tesla
X-Forwarded-For: 172.20.0.1
X-Forwarded-Host: whoami.localhost
X-Forwarded-Port: 80
X-Forwarded-Proto: http
X-Forwarded-Server: e6b851ac536d
X-Real-Ip: 172.20.0.1
```

If a wrong password is provided:
```bash
curl --user tesla:password-wrong -H "Host: whoami.localhost" http://0.0.0.0
```

You should got the `LDAP` related error:
```text
401 Unauthorized
Error: [LDAP Result Code 49 "Invalid Credentials": ]
```