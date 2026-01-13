# LDAP Role Manager

[![Go Report Card](https://goreportcard.com/badge/github.com/casbin/ldap-role-manager)](https://goreportcard.com/report/github.com/casbin/ldap-role-manager)
[![Go](https://github.com/casbin/ldap-role-manager/actions/workflows/ci.yml/badge.svg)](https://github.com/casbin/ldap-role-manager/actions/workflows/ci.yml)
[![Coverage Status](https://coveralls.io/repos/github/casbin/ldap-role-manager/badge.svg?branch=master)](https://coveralls.io/github/casbin/ldap-role-manager?branch=master)
[![Godoc](https://godoc.org/github.com/casbin/ldap-role-manager?status.svg)](https://godoc.org/github.com/casbin/ldap-role-manager)
[![Release](https://img.shields.io/github/release/casbin/ldap-role-manager.svg)](https://github.com/casbin/ldap-role-manager/releases/latest)
[![Discord](https://img.shields.io/discord/1022748306096537660?logo=discord&label=discord&color=5865F2)](https://discord.gg/S5UjpzGZjN)

LDAP Role Manager is an LDAP-based role manager for [Casbin](https://github.com/casbin/casbin). With this library, Casbin can load role hierarchies and user-role mappings from LDAP directories like Active Directory, OpenLDAP, etc.

## Installation

```bash
go get github.com/casbin/ldap-role-manager
```

## Simple Example

```go
package main

import (
	"fmt"
	"log"

	"github.com/casbin/casbin/v2"
	ldaprolemanager "github.com/casbin/ldap-role-manager"
)

func main() {
	// Initialize LDAP role manager
	opts := &ldaprolemanager.LDAPOptions{
		URL:               "ldap://localhost:389",
		BaseDN:            "dc=example,dc=com",
		UserFilter:        "(uid=%s)",
		GroupFilter:       "(member=%s)",
		RoleAttr:          "cn",
		BindDN:            "cn=admin,dc=example,dc=com",
		BindPassword:      "password",
		MaxHierarchyLevel: 10,
	}

	rm, err := ldaprolemanager.NewRoleManager(opts)
	if err != nil {
		log.Fatalf("Failed to create role manager: %v", err)
	}
	defer rm.Close()

	// Create a new enforcer
	e, err := casbin.NewEnforcer("examples/rbac_model.conf", "examples/rbac_policy.csv")
	if err != nil {
		log.Fatalf("Failed to create enforcer: %v", err)
	}

	// Set the role manager
	e.SetRoleManager(rm)

	// Load policy
	err = e.LoadPolicy()
	if err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}

	// Check permissions
	if res, _ := e.Enforce("alice", "data1", "read"); res {
		fmt.Println("alice can read data1")
	} else {
		fmt.Println("alice cannot read data1")
	}
}
```

## Configuration Options

The `LDAPOptions` struct supports the following configuration options:

- **URL**: LDAP server URL (e.g., `ldap://localhost:389` or `ldaps://localhost:636`)
- **BaseDN**: Base distinguished name for searching (e.g., `dc=example,dc=com`)
- **UserFilter**: LDAP filter template for finding users (e.g., `(uid=%s)`)
- **GroupFilter**: LDAP filter template for finding groups (e.g., `(member=%s)`)
- **RoleAttr**: Attribute name containing role/group names (default: `cn`)
- **BindDN**: Distinguished name for binding to LDAP (optional)
- **BindPassword**: Password for binding to LDAP (optional)
- **UseTLS**: Enable TLS connection (default: `false`)
- **SkipTLSVerify**: Skip TLS certificate verification (default: `false`)
- **MaxHierarchyLevel**: Maximum depth for role hierarchy traversal (default: `10`)

## LDAP Schema Requirements

This role manager expects the following LDAP schema:

### User Entries
- Users should be identifiable by the `UserFilter` (e.g., `uid` attribute)
- Example: `uid=alice,ou=users,dc=example,dc=com`

### Group Entries
- Groups should contain a `member` attribute listing user DNs
- Groups should have a role name attribute (configured via `RoleAttr`, default is `cn`)
- Example: `cn=admin,ou=groups,dc=example,dc=com`

### Example LDIF

```ldif
# User entry
dn: uid=alice,ou=users,dc=example,dc=com
objectClass: inetOrgPerson
uid: alice
cn: Alice Smith
sn: Smith

# Group entry
dn: cn=admin,ou=groups,dc=example,dc=com
objectClass: groupOfNames
cn: admin
member: uid=alice,ou=users,dc=example,dc=com
```

## Active Directory Example

For Active Directory, you might use different filters:

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

## Features

- **Read-only Role Management**: Roles are managed in LDAP, not in Casbin policies
- **Role Hierarchy Support**: Supports nested group memberships up to `MaxHierarchyLevel`
- **Multiple Group Membership**: Users can belong to multiple groups/roles
- **Flexible LDAP Schema**: Configurable filters and attributes to match your LDAP schema
- **TLS Support**: Secure connections to LDAP servers
- **Thread-safe**: Safe for concurrent use

## API

The LDAP Role Manager implements the `rbac.RoleManager` interface:

- `GetRoles(name string, domain ...string) ([]string, error)` - Get roles for a user
- `GetUsers(roleName string, domain ...string) ([]string, error)` - Get users with a specific role
- `HasLink(name1 string, name2 string, domain ...string) (bool, error)` - Check if a user has a role
- `GetImplicitRoles(name string, domain ...string) ([]string, error)` - Get all roles including nested ones
- `GetImplicitUsers(roleName string, domain ...string) ([]string, error)` - Get all users with a role

Note: Methods like `AddLink` and `DeleteLink` are no-ops since roles are managed in LDAP.

## Testing

Run the tests with:

```bash
go test -v ./...
```

For tests with coverage:

```bash
go test -v -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

## Related Projects

- [Casbin](https://github.com/casbin/casbin) - Authorization library
- [Gorm Adapter](https://github.com/casbin/gorm-adapter) - Casbin adapter for GORM
- [Redis Watcher](https://github.com/casbin/redis-watcher) - Redis watcher for Casbin
- [Etcd Watcher](https://github.com/casbin/etcd-watcher) - Etcd watcher for Casbin

## Getting Help

- [Casbin Documentation](https://casbin.org/)
- [GitHub Issues](https://github.com/casbin/ldap-role-manager/issues)
- [Discord](https://discord.gg/S5UjpzGZjN)

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE) file for the full license text.
