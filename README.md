# LDAP Role Manager

[![Go](https://github.com/casbin/ldap-role-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/casbin/ldap-role-manager/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/casbin/ldap-role-manager)](https://goreportcard.com/report/github.com/casbin/ldap-role-manager)
[![Go Reference](https://pkg.go.dev/badge/github.com/casbin/ldap-role-manager.svg)](https://pkg.go.dev/github.com/casbin/ldap-role-manager)
[![Release](https://img.shields.io/github/release/casbin/ldap-role-manager.svg)](https://github.com/casbin/ldap-role-manager/releases/latest)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)

LDAP Role Manager is an LDAP-based role manager for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load roles and users directly from LDAP directory services like Active Directory, OpenLDAP, etc.

## Installation

```bash
go get github.com/casbin/ldap-role-manager
```

## Features

- **LDAP Integration**: Connect to any LDAP-compliant directory service
- **Role Hierarchy**: Support for nested group memberships
- **Flexible Configuration**: Customizable LDAP filters and attributes
- **Thread-Safe**: Concurrent access supported with mutex protection
- **TLS Support**: Secure connections with configurable TLS
- **Domain Support**: Multi-domain/tenant support

## Quick Start

```go
package main

import (
    "log"
    
    "github.com/casbin/casbin/v3"
    ldaprm "github.com/casbin/ldap-role-manager"
)

func main() {
    // Create a new LDAP role manager
    rm := ldaprm.NewRoleManager("localhost", 389)
    
    // Configure LDAP settings
    rm.SetBaseDN("dc=example,dc=com")
    rm.SetBindCredentials("cn=admin,dc=example,dc=com", "password")
    
    // Connect to LDAP server
    err := rm.Connect()
    if err != nil {
        log.Fatal(err)
    }
    defer rm.Close()
    
    // Create a Casbin enforcer with the LDAP role manager
    e, err := casbin.NewEnforcer("model.conf", "policy.csv")
    if err != nil {
        log.Fatal(err)
    }
    
    // Set the role manager
    e.SetRoleManager(rm)
    
    // Now you can enforce policies with LDAP roles
    if ok, err := e.Enforce("alice", "data1", "read"); err != nil {
        log.Fatal(err)
    } else if ok {
        log.Println("Access granted")
    } else {
        log.Println("Access denied")
    }
}
```

## Configuration

### Basic Configuration

```go
rm := ldaprm.NewRoleManager("ldap.example.com", 389)

// Set base DN for LDAP searches
rm.SetBaseDN("dc=example,dc=com")

// Set bind credentials (if required by your LDAP server)
rm.SetBindCredentials("cn=admin,dc=example,dc=com", "password")
```

### TLS Configuration

```go
import "crypto/tls"

// Enable TLS with custom configuration
tlsConfig := &tls.Config{
    ServerName: "ldap.example.com",
    InsecureSkipVerify: false,
}
rm.SetTLS(tlsConfig)
```

### Custom Filters and Attributes

```go
// Customize LDAP filters
rm.SetUserFilter("(&(objectClass=inetOrgPerson)(uid=%s))")
rm.SetGroupFilter("(&(objectClass=groupOfNames)(member=%s))")

// Customize attribute names
rm.SetUserNameAttribute("uid")
rm.SetGroupNameAttribute("cn")
rm.SetMemberAttribute("member")

// Set maximum depth for role hierarchy traversal
rm.SetMaxDepth(10)
```

## Model Configuration

Example Casbin model file (`model.conf`):

```ini
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

Example policy file (`policy.csv`):

```csv
p, admin-group, data1, read
p, admin-group, data1, write
p, user-group, data1, read
```

## How It Works

The LDAP Role Manager integrates with Casbin by implementing the `rbac.RoleManager` interface. When Casbin needs to check if a user has a certain role:

1. The role manager queries the LDAP server to find the user's DN (Distinguished Name)
2. It then searches for all groups the user is a member of
3. These groups are returned as roles to Casbin
4. Casbin uses these roles for policy matching

## LDAP Directory Structure

The role manager works with standard LDAP directory structures. Here's an example:

```
dc=example,dc=com
├── ou=users
│   ├── uid=alice,ou=users,dc=example,dc=com
│   ├── uid=bob,ou=users,dc=example,dc=com
│   └── uid=charlie,ou=users,dc=example,dc=com
└── ou=groups
    ├── cn=admin-group,ou=groups,dc=example,dc=com (members: alice)
    ├── cn=user-group,ou=groups,dc=example,dc=com (members: bob, charlie)
    └── cn=support-group,ou=groups,dc=example,dc=com (members: charlie)
```

## API Reference

### Constructor

- `NewRoleManager(host string, port int) *RoleManager` - Creates a new LDAP role manager instance

### Configuration Methods

- `SetTLS(config *tls.Config)` - Enable TLS with custom config
- `SetBaseDN(baseDN string)` - Set base DN for searches
- `SetBindCredentials(userDN, password string)` - Set bind credentials
- `SetUserFilter(filter string)` - Set user search filter (default: `"(&(objectClass=person)(uid=%s))"`)
- `SetGroupFilter(filter string)` - Set group search filter (default: `"(&(objectClass=groupOfNames)(member=%s))"`)
- `SetUserNameAttribute(attr string)` - Set user name attribute (default: `"uid"`)
- `SetGroupNameAttribute(attr string)` - Set group name attribute (default: `"cn"`)
- `SetMemberAttribute(attr string)` - Set member attribute (default: `"member"`)
- `SetMaxDepth(depth int)` - Set max depth for role hierarchy (default: `10`)

### Connection Methods

- `Connect() error` - Establish connection to LDAP server
- `Close() error` - Close the LDAP connection

### RoleManager Interface Methods

- `Clear() error` - Clear all stored data
- `AddLink(name1, name2 string, domain ...string) error` - No-op (roles managed in LDAP)
- `DeleteLink(name1, name2 string, domain ...string) error` - No-op (roles managed in LDAP)
- `HasLink(name1, name2 string, domain ...string) (bool, error)` - Check if role link exists
- `GetRoles(name string, domain ...string) ([]string, error)` - Get roles for a user
- `GetUsers(name string, domain ...string) ([]string, error)` - Get users with a role
- `GetImplicitRoles(name string, domain ...string) ([]string, error)` - Get implicit roles (including nested)
- `GetImplicitUsers(name string, domain ...string) ([]string, error)` - Get implicit users for a role
- `GetDomains(name string) ([]string, error)` - Get domains for a user
- `GetAllDomains() ([]string, error)` - Get all domains
- `PrintRoles() error` - Print roles (no-op for LDAP)
- `Match(str, pattern string) bool` - Match with custom function
- `AddMatchingFunc(name string, fn MatchingFunc)` - Add custom matching function
- `AddDomainMatchingFunc(name string, fn MatchingFunc)` - Add custom domain matching function
- `DeleteDomain(domain string) error` - Delete a domain

## Supported LDAP Servers

This role manager should work with any LDAP v3 compliant directory service, including:

- OpenLDAP
- Microsoft Active Directory
- Apache Directory Server
- FreeIPA
- 389 Directory Server
- Oracle Directory Server

## Testing

Run the tests:

```bash
go test -v ./...
```

Run tests with coverage:

```bash
go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Casbin](https://github.com/casbin/casbin) - The authorization library that this role manager works with
- [go-ldap](https://github.com/go-ldap/ldap) - LDAP client library for Go

## Getting Help

- [Casbin Discord](https://discord.gg/S5UjpzGZjN)
- [Casbin Forum](https://forum.casbin.com/)
- [GitHub Issues](https://github.com/casbin/ldap-role-manager/issues)
