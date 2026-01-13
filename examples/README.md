# Examples

This directory contains examples demonstrating how to use the LDAP Role Manager with Casbin.

## Files

- **main.go** - A simple example showing how to integrate LDAP role manager with Casbin
- **rbac_model.conf** - Casbin RBAC model configuration
- **rbac_policy.csv** - Sample policies for role-based access control
- **example.ldif** - Sample LDIF file for populating an LDAP directory

## Running the Example

### 1. Set up an LDAP Server

You can use OpenLDAP or any other LDAP server. For testing, you can use Docker:

```bash
docker run -d \
  --name openldap \
  -p 389:389 \
  -e LDAP_ORGANISATION="Example Inc." \
  -e LDAP_DOMAIN="example.com" \
  -e LDAP_ADMIN_PASSWORD="admin" \
  osixia/openldap:latest
```

### 2. Populate the LDAP Directory

Load the example LDIF file into your LDAP server:

```bash
# Using ldapadd
ldapadd -x -D "cn=admin,dc=example,dc=com" -w admin -f example.ldif

# Or using Docker
docker exec openldap ldapadd -x -D "cn=admin,dc=example,dc=com" -w admin -f /tmp/example.ldif
```

You may need to copy the LDIF file into the container first:

```bash
docker cp example.ldif openldap:/tmp/example.ldif
```

### 3. Run the Example

Update the connection details in `main.go` if needed, then run:

```bash
cd examples
go run main.go
```

## Expected Output

The example will check permissions for alice (admin) and bob (user):

```
✓ alice can read data1
✓ alice can write data1
✓ bob can read data1
✗ bob cannot write data1

Roles for alice: [admin user]
Roles for bob: [user]
```

## Verifying LDAP Setup

You can verify your LDAP setup using ldapsearch:

```bash
# Search for all users
ldapsearch -x -D "cn=admin,dc=example,dc=com" -w admin -b "ou=users,dc=example,dc=com"

# Search for all groups
ldapsearch -x -D "cn=admin,dc=example,dc=com" -w admin -b "ou=groups,dc=example,dc=com"

# Search for alice's groups
ldapsearch -x -D "cn=admin,dc=example,dc=com" -w admin -b "dc=example,dc=com" "(member=uid=alice,ou=users,dc=example,dc=com)"
```

## Customization

You can customize the example by:

1. Modifying the LDAP connection parameters in `main.go`
2. Adding more users and groups to `example.ldif`
3. Creating different policies in `rbac_policy.csv`
4. Adjusting the model in `rbac_model.conf`

## Active Directory Example

For Active Directory, you would use different filters and configuration:

```go
opts := &ldaprolemanager.LDAPOptions{
    URL:          "ldaps://ad.example.com:636",
    BaseDN:       "dc=example,dc=com",
    UserFilter:   "(sAMAccountName=%s)",
    GroupFilter:  "(member=%s)",
    RoleAttr:     "cn",
    BindDN:       "cn=service-account,ou=users,dc=example,dc=com",
    BindPassword: "password",
    UseTLS:       true,
}
```
