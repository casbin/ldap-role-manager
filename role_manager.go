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
	"container/list"
	"crypto/tls"
	"errors"
	"fmt"
	"sync"

	"github.com/casbin/casbin/v3/rbac"
	"github.com/go-ldap/ldap/v3"
)

// RoleManager is an LDAP-based role manager for Casbin.
// It provides role management functionality by querying LDAP directory.
type RoleManager struct {
	conn               *ldap.Conn
	mu                 sync.RWMutex
	host               string
	port               int
	useTLS             bool
	tlsConfig          *tls.Config
	baseDN             string
	userDN             string
	password           string
	userFilter         string
	groupFilter        string
	userNameAttribute  string
	groupNameAttribute string
	memberAttribute    string
	maxDepth           int
	matchingFunc       rbac.MatchingFunc
	domainMatchingFunc rbac.MatchingFunc
	allDomains         []string
	hasPolicyDomains   map[string]bool
}

// NewRoleManager creates a new LDAP role manager instance.
func NewRoleManager(host string, port int) *RoleManager {
	rm := &RoleManager{
		host:               host,
		port:               port,
		useTLS:             false,
		userFilter:         "(&(objectClass=person)(uid=%s))",
		groupFilter:        "(&(objectClass=groupOfNames)(member=%s))",
		userNameAttribute:  "uid",
		groupNameAttribute: "cn",
		memberAttribute:    "member",
		maxDepth:           10,
		allDomains:         []string{},
		hasPolicyDomains:   make(map[string]bool),
	}
	return rm
}

// SetTLS enables TLS connection with custom config.
func (rm *RoleManager) SetTLS(config *tls.Config) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.useTLS = true
	rm.tlsConfig = config
}

// SetBaseDN sets the base DN for LDAP searches.
func (rm *RoleManager) SetBaseDN(baseDN string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.baseDN = baseDN
}

// SetBindCredentials sets the credentials for binding to LDAP.
func (rm *RoleManager) SetBindCredentials(userDN, password string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.userDN = userDN
	rm.password = password
}

// SetUserFilter sets the LDAP filter for user searches.
func (rm *RoleManager) SetUserFilter(filter string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.userFilter = filter
}

// SetGroupFilter sets the LDAP filter for group searches.
func (rm *RoleManager) SetGroupFilter(filter string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.groupFilter = filter
}

// SetUserNameAttribute sets the attribute name for user names.
func (rm *RoleManager) SetUserNameAttribute(attr string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.userNameAttribute = attr
}

// SetGroupNameAttribute sets the attribute name for group names.
func (rm *RoleManager) SetGroupNameAttribute(attr string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.groupNameAttribute = attr
}

// SetMemberAttribute sets the attribute name for group members.
func (rm *RoleManager) SetMemberAttribute(attr string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.memberAttribute = attr
}

// SetMaxDepth sets the maximum depth for role hierarchy traversal.
func (rm *RoleManager) SetMaxDepth(depth int) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.maxDepth = depth
}

// Connect establishes connection to LDAP server.
func (rm *RoleManager) Connect() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	var err error
	addr := fmt.Sprintf("%s:%d", rm.host, rm.port)

	if rm.useTLS {
		rm.conn, err = ldap.DialTLS("tcp", addr, rm.tlsConfig)
	} else {
		rm.conn, err = ldap.Dial("tcp", addr)
	}

	if err != nil {
		return fmt.Errorf("failed to connect to LDAP server: %w", err)
	}

	if rm.userDN != "" && rm.password != "" {
		err = rm.conn.Bind(rm.userDN, rm.password)
		if err != nil {
			rm.conn.Close()
			rm.conn = nil
			return fmt.Errorf("failed to bind to LDAP server: %w", err)
		}
	}

	return nil
}

// Close closes the LDAP connection.
func (rm *RoleManager) Close() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	if rm.conn != nil {
		rm.conn.Close()
		rm.conn = nil
	}
	return nil
}

// Clear clears all stored data and resets the role manager to the initial state.
func (rm *RoleManager) Clear() error {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.allDomains = []string{}
	rm.hasPolicyDomains = make(map[string]bool)
	return nil
}

// AddLink adds the inheritance link between two roles.
// For LDAP role manager, this is a no-op as roles are managed in LDAP.
func (rm *RoleManager) AddLink(name1 string, name2 string, domain ...string) error {
	// LDAP role manager is read-only, roles are managed in LDAP
	return nil
}

// BuildRelationship is deprecated and not required.
func (rm *RoleManager) BuildRelationship(name1 string, name2 string, domain ...string) error {
	return nil
}

// DeleteLink deletes the inheritance link between two roles.
// For LDAP role manager, this is a no-op as roles are managed in LDAP.
func (rm *RoleManager) DeleteLink(name1 string, name2 string, domain ...string) error {
	// LDAP role manager is read-only, roles are managed in LDAP
	return nil
}

// HasLink determines whether a link exists between two roles.
func (rm *RoleManager) HasLink(name1 string, name2 string, domain ...string) (bool, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if rm.conn == nil {
		return false, errors.New("LDAP connection not established")
	}

	roles, err := rm.getRolesInternal(name1, domain...)
	if err != nil {
		return false, err
	}

	for _, role := range roles {
		if role == name2 {
			return true, nil
		}
		if rm.matchingFunc != nil && rm.matchingFunc(name2, role) {
			return true, nil
		}
	}

	return false, nil
}

// GetRoles gets the roles that a user inherits.
func (rm *RoleManager) GetRoles(name string, domain ...string) ([]string, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if rm.conn == nil {
		return nil, errors.New("LDAP connection not established")
	}

	return rm.getRolesInternal(name, domain...)
}

// getRolesInternal is the internal implementation of GetRoles without locking.
func (rm *RoleManager) getRolesInternal(name string, domain ...string) ([]string, error) {
	// Build search request for user
	userFilter := fmt.Sprintf(rm.userFilter, ldap.EscapeFilter(name))
	searchRequest := ldap.NewSearchRequest(
		rm.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
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

	// Search for groups the user belongs to
	groupFilter := fmt.Sprintf(rm.groupFilter, ldap.EscapeFilter(userDN))
	groupSearchRequest := ldap.NewSearchRequest(
		rm.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		groupFilter,
		[]string{rm.groupNameAttribute},
		nil,
	)

	gsr, err := rm.conn.Search(groupSearchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search for groups: %w", err)
	}

	var roles []string
	for _, entry := range gsr.Entries {
		groupName := entry.GetAttributeValue(rm.groupNameAttribute)
		if groupName != "" {
			roles = append(roles, groupName)
		}
	}

	return roles, nil
}

// GetUsers gets the users that inherits a role.
func (rm *RoleManager) GetUsers(name string, domain ...string) ([]string, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if rm.conn == nil {
		return nil, errors.New("LDAP connection not established")
	}

	// Search for the group by name
	// Build a filter to find a group with the specified name
	groupFilter := fmt.Sprintf("(&(objectClass=groupOfNames)(%s=%s))", rm.groupNameAttribute, ldap.EscapeFilter(name))
	searchRequest := ldap.NewSearchRequest(
		rm.baseDN,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false,
		groupFilter,
		[]string{rm.memberAttribute},
		nil,
	)

	sr, err := rm.conn.Search(searchRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to search for group: %w", err)
	}

	if len(sr.Entries) == 0 {
		return []string{}, nil
	}

	// Get members from the group
	members := sr.Entries[0].GetAttributeValues(rm.memberAttribute)
	if len(members) == 0 {
		return []string{}, nil
	}

	// Query each member DN individually for maximum LDAP compatibility
	// This approach works reliably across all LDAP server implementations
	var users []string
	for _, memberDN := range members {
		userSearchRequest := ldap.NewSearchRequest(
			memberDN,
			ldap.ScopeBaseObject, ldap.NeverDerefAliases, 0, 0, false,
			"(objectClass=*)",
			[]string{rm.userNameAttribute},
			nil,
		)

		usr, err := rm.conn.Search(userSearchRequest)
		if err == nil && len(usr.Entries) > 0 {
			userName := usr.Entries[0].GetAttributeValue(rm.userNameAttribute)
			if userName != "" {
				users = append(users, userName)
			}
		}
	}

	return users, nil
}

// GetImplicitRoles gets the implicit roles that a user inherits.
func (rm *RoleManager) GetImplicitRoles(name string, domain ...string) ([]string, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()

	if rm.conn == nil {
		return nil, errors.New("LDAP connection not established")
	}

	allRoles := make(map[string]bool)
	queue := list.New()
	queue.PushBack(name)
	visited := make(map[string]bool)
	depth := 0

	for queue.Len() > 0 && depth < rm.maxDepth {
		element := queue.Front()
		current := element.Value.(string)
		queue.Remove(element)

		if visited[current] {
			continue
		}
		visited[current] = true

		roles, err := rm.getRolesInternal(current, domain...)
		if err != nil {
			return nil, err
		}

		for _, role := range roles {
			if !allRoles[role] {
				allRoles[role] = true
				queue.PushBack(role)
			}
		}
		depth++
	}

	var result []string
	for role := range allRoles {
		result = append(result, role)
	}

	return result, nil
}

// GetImplicitUsers gets the implicit users that inherits a role.
func (rm *RoleManager) GetImplicitUsers(name string, domain ...string) ([]string, error) {
	// For LDAP, we typically don't need to traverse upward for implicit users
	// Just return direct users
	return rm.GetUsers(name, domain...)
}

// GetDomains gets domains that a user has.
func (rm *RoleManager) GetDomains(name string) ([]string, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.allDomains, nil
}

// GetAllDomains gets all domains.
func (rm *RoleManager) GetAllDomains() ([]string, error) {
	rm.mu.RLock()
	defer rm.mu.RUnlock()
	return rm.allDomains, nil
}

// PrintRoles prints all the roles to log.
func (rm *RoleManager) PrintRoles() error {
	// This is mainly for debugging, LDAP doesn't maintain local role state
	return nil
}

// Match matches the domain with the pattern.
func (rm *RoleManager) Match(str string, pattern string) bool {
	if rm.matchingFunc != nil {
		return rm.matchingFunc(str, pattern)
	}
	return str == pattern
}

// AddMatchingFunc adds the matching function.
func (rm *RoleManager) AddMatchingFunc(name string, fn rbac.MatchingFunc) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.matchingFunc = fn
}

// AddDomainMatchingFunc adds the domain matching function.
func (rm *RoleManager) AddDomainMatchingFunc(name string, fn rbac.MatchingFunc) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.domainMatchingFunc = fn
}

// DeleteDomain deletes all data of a domain in the role manager.
func (rm *RoleManager) DeleteDomain(domain string) error {
	rm.mu.Lock()
	defer rm.mu.Unlock()

	delete(rm.hasPolicyDomains, domain)

	// Remove from allDomains
	newDomains := []string{}
	for _, d := range rm.allDomains {
		if d != domain {
			newDomains = append(newDomains, d)
		}
	}
	rm.allDomains = newDomains

	return nil
}
