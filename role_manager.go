// Copyright 2026 The casbin Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ldaprolemanager

import (
	"crypto/tls"
	"fmt"
	"strings"
	"sync"

	"github.com/casbin/casbin/v2/rbac"
	"github.com/go-ldap/ldap/v3"
)

// LDAPConn defines the interface for LDAP operations.
type LDAPConn interface {
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	Bind(username, password string) error
	Close() error
}

// RoleManager implements the RoleManager interface for LDAP.
type RoleManager struct {
	allDomains        map[string]struct{}
	maxHierarchyLevel int
	conn              LDAPConn
	ldapURL           string
	baseDN            string
	userFilter        string
	groupFilter       string
	roleAttr          string
	mutex             sync.RWMutex
}

// LDAPOptions contains configuration options for LDAP connection.
type LDAPOptions struct {
	// LDAP server URL (e.g., "ldap://localhost:389" or "ldaps://localhost:636")
	URL string
	// Base DN for searching (e.g., "dc=example,dc=com")
	BaseDN string
	// User filter template (e.g., "(uid=%s)")
	UserFilter string
	// Group filter template (e.g., "(member=%s)")
	GroupFilter string
	// Attribute containing role/group names (default: "cn")
	RoleAttr string
	// Bind DN for authentication
	BindDN string
	// Bind password
	BindPassword string
	// Use TLS
	UseTLS bool
	// Skip TLS verification
	SkipTLSVerify bool
	// Maximum hierarchy level for role inheritance (default: 10)
	MaxHierarchyLevel int
}

// NewRoleManager creates a new RoleManager instance with LDAP connection.
func NewRoleManager(opts *LDAPOptions) (*RoleManager, error) {
	rm := &RoleManager{
		allDomains:        make(map[string]struct{}),
		maxHierarchyLevel: opts.MaxHierarchyLevel,
		ldapURL:           opts.URL,
		baseDN:            opts.BaseDN,
		userFilter:        opts.UserFilter,
		groupFilter:       opts.GroupFilter,
		roleAttr:          opts.RoleAttr,
	}

	if rm.maxHierarchyLevel == 0 {
		rm.maxHierarchyLevel = 10
	}

	if rm.roleAttr == "" {
		rm.roleAttr = "cn"
	}

	if rm.userFilter == "" {
		rm.userFilter = "(uid=%s)"
	}

	if rm.groupFilter == "" {
		rm.groupFilter = "(member=%s)"
	}

	// Establish LDAP connection
	var err error
	if opts.UseTLS {
		tlsConfig := &tls.Config{
			InsecureSkipVerify: opts.SkipTLSVerify,
		}
		rm.conn, err = ldap.DialURL(opts.URL, ldap.DialWithTLSConfig(tlsConfig))
	} else {
		rm.conn, err = ldap.DialURL(opts.URL)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	// Bind if credentials are provided
	if opts.BindDN != "" {
		err = rm.conn.Bind(opts.BindDN, opts.BindPassword)
		if err != nil {
			rm.conn.Close()
			return nil, fmt.Errorf("failed to bind to LDAP server: %w", err)
		}
	}

	return rm, nil
}

// Close closes the LDAP connection.
func (rm *RoleManager) Close() error {
	if rm.conn != nil {
		rm.conn.Close()
	}
	return nil
}

// Clear clears all stored data and resets the role manager to the initial state.
func (rm *RoleManager) Clear() error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	rm.allDomains = make(map[string]struct{})
	return nil
}

// AddLink adds the inheritance link between role: name1 and role: name2.
// For LDAP role manager, this is a no-op as roles are managed in LDAP.
func (rm *RoleManager) AddLink(name1 string, name2 string, domain ...string) error {
	// LDAP roles are read-only from the directory service
	return nil
}

// BuildRelationship builds the relationship between role: name1 and role: name2.
// Deprecated: BuildRelationship is no longer required
func (rm *RoleManager) BuildRelationship(name1 string, name2 string, domain ...string) error {
	return nil
}

// DeleteLink deletes the inheritance link between role: name1 and role: name2.
// For LDAP role manager, this is a no-op as roles are managed in LDAP.
func (rm *RoleManager) DeleteLink(name1 string, name2 string, domain ...string) error {
	// LDAP roles are read-only from the directory service
	return nil
}

// HasLink determines whether role: name1 inherits role: name2.
func (rm *RoleManager) HasLink(name1 string, name2 string, domain ...string) (bool, error) {
	roles, err := rm.GetRoles(name1, domain...)
	if err != nil {
		return false, err
	}

	for _, role := range roles {
		if role == name2 {
			return true, nil
		}
	}

	return false, nil
}

// GetRoles gets the roles that a user inherits.
func (rm *RoleManager) GetRoles(name string, domain ...string) ([]string, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	if rm.conn == nil {
		return nil, fmt.Errorf("LDAP connection is not established")
	}

	// Search for user
	userFilter := fmt.Sprintf(rm.userFilter, ldap.EscapeFilter(name))
	searchRequest := ldap.NewSearchRequest(
		rm.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		userFilter,
		[]string{"dn"},
		nil,
	)

	sr, err := rm.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search for user: %w", err)
	}

	if len(sr.Entries) == 0 {
		return []string{}, nil
	}

	userDN := sr.Entries[0].DN

	// Search for groups the user is a member of
	groupFilter := fmt.Sprintf(rm.groupFilter, ldap.EscapeFilter(userDN))
	groupSearchRequest := ldap.NewSearchRequest(
		rm.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		groupFilter,
		[]string{rm.roleAttr},
		nil,
	)

	gsr, err := rm.conn.Search(groupSearchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search for groups: %w", err)
	}

	roles := make([]string, 0, len(gsr.Entries))
	for _, entry := range gsr.Entries {
		roleName := entry.GetAttributeValue(rm.roleAttr)
		if roleName != "" {
			roles = append(roles, roleName)
		}
	}

	return roles, nil
}

// GetUsers gets the users that inherits a role.
func (rm *RoleManager) GetUsers(roleName string, domain ...string) ([]string, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	if rm.conn == nil {
		return nil, fmt.Errorf("LDAP connection is not established")
	}

	// First, find the group DN
	groupFilter := fmt.Sprintf("(&(objectClass=groupOfNames)(%s=%s))", rm.roleAttr, ldap.EscapeFilter(roleName))
	searchRequest := ldap.NewSearchRequest(
		rm.baseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		0,
		0,
		false,
		groupFilter,
		[]string{"member"},
		nil,
	)

	sr, err := rm.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search for group: %w", err)
	}

	if len(sr.Entries) == 0 {
		return []string{}, nil
	}

	members := sr.Entries[0].GetAttributeValues("member")
	users := make([]string, 0, len(members))

	for _, memberDN := range members {
		// Extract user identifier from DN
		// This is a simplified extraction; you may need to customize based on your LDAP schema
		parts := strings.Split(memberDN, ",")
		if len(parts) > 0 {
			uidPart := parts[0]
			uidParts := strings.Split(uidPart, "=")
			if len(uidParts) == 2 {
				users = append(users, uidParts[1])
			}
		}
	}

	return users, nil
}

// GetImplicitRoles gets the implicit roles that a user inherits, respecting maxHierarchyLevel.
func (rm *RoleManager) GetImplicitRoles(name string, domain ...string) ([]string, error) {
	allRoles := make(map[string]struct{})
	queue := []string{name}
	level := 0

	for len(queue) > 0 && level < rm.maxHierarchyLevel {
		var nextQueue []string
		for _, current := range queue {
			roles, err := rm.GetRoles(current, domain...)
			if err != nil {
				return nil, err
			}

			for _, role := range roles {
				if _, exists := allRoles[role]; !exists {
					allRoles[role] = struct{}{}
					nextQueue = append(nextQueue, role)
				}
			}
		}
		queue = nextQueue
		level++
	}

	result := make([]string, 0, len(allRoles))
	for role := range allRoles {
		result = append(result, role)
	}

	return result, nil
}

// GetImplicitUsers gets the implicit users that inherits a role, respecting maxHierarchyLevel.
func (rm *RoleManager) GetImplicitUsers(roleName string, domain ...string) ([]string, error) {
	allUsers := make(map[string]struct{})

	users, err := rm.GetUsers(roleName, domain...)
	if err != nil {
		return nil, err
	}

	for _, user := range users {
		allUsers[user] = struct{}{}
	}

	result := make([]string, 0, len(allUsers))
	for user := range allUsers {
		result = append(result, user)
	}

	return result, nil
}

// GetDomains gets domains that a user has.
func (rm *RoleManager) GetDomains(name string) ([]string, error) {
	return []string{}, nil
}

// GetAllDomains gets all domains.
func (rm *RoleManager) GetAllDomains() ([]string, error) {
	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	domains := make([]string, 0, len(rm.allDomains))
	for domain := range rm.allDomains {
		domains = append(domains, domain)
	}
	return domains, nil
}

// PrintRoles prints all the roles to log.
func (rm *RoleManager) PrintRoles() error {
	return nil
}

// Match matches the domain with the pattern.
func (rm *RoleManager) Match(str string, pattern string) bool {
	return str == pattern
}

// AddMatchingFunc adds the matching function.
func (rm *RoleManager) AddMatchingFunc(name string, fn rbac.MatchingFunc) {
	// Not supported in LDAP role manager
}

// AddDomainMatchingFunc adds the domain matching function.
func (rm *RoleManager) AddDomainMatchingFunc(name string, fn rbac.MatchingFunc) {
	// Not supported in LDAP role manager
}

// DeleteDomain deletes all data of a domain in the role manager.
func (rm *RoleManager) DeleteDomain(domain string) error {
	rm.mutex.Lock()
	defer rm.mutex.Unlock()
	delete(rm.allDomains, domain)
	return nil
}
