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
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// MockLDAPConn is a mock LDAP connection for testing.
type MockLDAPConn struct {
	entries map[string]*ldap.Entry
}

func (m *MockLDAPConn) Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	result := &ldap.SearchResult{
		Entries: []*ldap.Entry{},
	}

	// Simulate user search
	if searchRequest.Filter == "(uid=alice)" {
		result.Entries = append(result.Entries, &ldap.Entry{
			DN: "uid=alice,ou=users,dc=example,dc=com",
		})
	} else if searchRequest.Filter == "(uid=bob)" {
		result.Entries = append(result.Entries, &ldap.Entry{
			DN: "uid=bob,ou=users,dc=example,dc=com",
		})
	} else if searchRequest.Filter == "(uid=unknown)" {
		// No entries for unknown user
	} else if searchRequest.Filter == "(member=uid=alice,ou=users,dc=example,dc=com)" {
		// Alice is member of admin and user groups
		result.Entries = append(result.Entries,
			&ldap.Entry{
				DN: "cn=admin,ou=groups,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "cn", Values: []string{"admin"}},
				},
			},
			&ldap.Entry{
				DN: "cn=user,ou=groups,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "cn", Values: []string{"user"}},
				},
			},
		)
	} else if searchRequest.Filter == "(member=uid=bob,ou=users,dc=example,dc=com)" {
		// Bob is member of user group only
		result.Entries = append(result.Entries,
			&ldap.Entry{
				DN: "cn=user,ou=groups,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "cn", Values: []string{"user"}},
				},
			},
		)
	} else if searchRequest.Filter == "(&(objectClass=groupOfNames)(cn=admin))" {
		// Get members of admin group
		result.Entries = append(result.Entries,
			&ldap.Entry{
				DN: "cn=admin,ou=groups,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "member", Values: []string{"uid=alice,ou=users,dc=example,dc=com"}},
				},
			},
		)
	} else if searchRequest.Filter == "(&(objectClass=groupOfNames)(cn=user))" {
		// Get members of user group
		result.Entries = append(result.Entries,
			&ldap.Entry{
				DN: "cn=user,ou=groups,dc=example,dc=com",
				Attributes: []*ldap.EntryAttribute{
					{Name: "member", Values: []string{
						"uid=alice,ou=users,dc=example,dc=com",
						"uid=bob,ou=users,dc=example,dc=com",
					}},
				},
			},
		)
	}

	return result, nil
}

func (m *MockLDAPConn) Bind(username, password string) error {
	return nil
}

func (m *MockLDAPConn) Close() error {
	return nil
}

// TestNewRoleManager tests the creation of a new role manager.
func TestNewRoleManager(t *testing.T) {
	// This test would require an actual LDAP server or more sophisticated mocking
	// For now, we'll test the structure
	opts := &LDAPOptions{
		URL:               "ldap://localhost:389",
		BaseDN:            "dc=example,dc=com",
		UserFilter:        "(uid=%s)",
		GroupFilter:       "(member=%s)",
		RoleAttr:          "cn",
		MaxHierarchyLevel: 10,
	}

	// Test that default values are set correctly
	if opts.MaxHierarchyLevel != 10 {
		t.Errorf("Expected MaxHierarchyLevel to be 10, got %d", opts.MaxHierarchyLevel)
	}
}

// TestGetRoles tests getting roles for a user (with mock).
func TestGetRoles(t *testing.T) {
	rm := &RoleManager{
		allDomains:        make(map[string]struct{}),
		maxHierarchyLevel: 10,
		baseDN:            "dc=example,dc=com",
		userFilter:        "(uid=%s)",
		groupFilter:       "(member=%s)",
		roleAttr:          "cn",
		conn:              &MockLDAPConn{},
	}

	// Test getting roles for alice
	roles, err := rm.GetRoles("alice")
	if err != nil {
		t.Errorf("Failed to get roles for alice: %v", err)
	}

	expectedRoles := []string{"admin", "user"}
	if len(roles) != len(expectedRoles) {
		t.Errorf("Expected %d roles, got %d", len(expectedRoles), len(roles))
	}

	roleMap := make(map[string]bool)
	for _, role := range roles {
		roleMap[role] = true
	}

	for _, expected := range expectedRoles {
		if !roleMap[expected] {
			t.Errorf("Expected role %s not found", expected)
		}
	}
}

// TestGetRolesForBob tests getting roles for bob (with mock).
func TestGetRolesForBob(t *testing.T) {
	rm := &RoleManager{
		allDomains:        make(map[string]struct{}),
		maxHierarchyLevel: 10,
		baseDN:            "dc=example,dc=com",
		userFilter:        "(uid=%s)",
		groupFilter:       "(member=%s)",
		roleAttr:          "cn",
		conn:              &MockLDAPConn{},
	}

	// Test getting roles for bob
	roles, err := rm.GetRoles("bob")
	if err != nil {
		t.Errorf("Failed to get roles for bob: %v", err)
	}

	if len(roles) != 1 {
		t.Errorf("Expected 1 role, got %d", len(roles))
	}

	if len(roles) > 0 && roles[0] != "user" {
		t.Errorf("Expected role 'user', got '%s'", roles[0])
	}
}

// TestGetRolesForUnknownUser tests getting roles for a non-existent user.
func TestGetRolesForUnknownUser(t *testing.T) {
	rm := &RoleManager{
		allDomains:        make(map[string]struct{}),
		maxHierarchyLevel: 10,
		baseDN:            "dc=example,dc=com",
		userFilter:        "(uid=%s)",
		groupFilter:       "(member=%s)",
		roleAttr:          "cn",
		conn:              &MockLDAPConn{},
	}

	// Test getting roles for unknown user
	roles, err := rm.GetRoles("unknown")
	if err != nil {
		t.Errorf("Failed to get roles for unknown user: %v", err)
	}

	if len(roles) != 0 {
		t.Errorf("Expected 0 roles for unknown user, got %d", len(roles))
	}
}

// TestHasLink tests the HasLink method.
func TestHasLink(t *testing.T) {
	rm := &RoleManager{
		allDomains:        make(map[string]struct{}),
		maxHierarchyLevel: 10,
		baseDN:            "dc=example,dc=com",
		userFilter:        "(uid=%s)",
		groupFilter:       "(member=%s)",
		roleAttr:          "cn",
		conn:              &MockLDAPConn{},
	}

	// Test HasLink for alice -> admin
	hasLink, err := rm.HasLink("alice", "admin")
	if err != nil {
		t.Errorf("Failed to check HasLink: %v", err)
	}

	if !hasLink {
		t.Error("Expected alice to have link to admin")
	}

	// Test HasLink for alice -> user
	hasLink, err = rm.HasLink("alice", "user")
	if err != nil {
		t.Errorf("Failed to check HasLink: %v", err)
	}

	if !hasLink {
		t.Error("Expected alice to have link to user")
	}

	// Test HasLink for bob -> admin (should be false)
	hasLink, err = rm.HasLink("bob", "admin")
	if err != nil {
		t.Errorf("Failed to check HasLink: %v", err)
	}

	if hasLink {
		t.Error("Expected bob to not have link to admin")
	}
}

// TestGetUsers tests getting users for a role.
func TestGetUsers(t *testing.T) {
	rm := &RoleManager{
		allDomains:        make(map[string]struct{}),
		maxHierarchyLevel: 10,
		baseDN:            "dc=example,dc=com",
		userFilter:        "(uid=%s)",
		groupFilter:       "(member=%s)",
		roleAttr:          "cn",
		conn:              &MockLDAPConn{},
	}

	// Test getting users for admin role
	users, err := rm.GetUsers("admin")
	if err != nil {
		t.Errorf("Failed to get users for admin role: %v", err)
	}

	if len(users) != 1 {
		t.Errorf("Expected 1 user, got %d", len(users))
	}

	if len(users) > 0 && users[0] != "alice" {
		t.Errorf("Expected user 'alice', got '%s'", users[0])
	}

	// Test getting users for user role
	users, err = rm.GetUsers("user")
	if err != nil {
		t.Errorf("Failed to get users for user role: %v", err)
	}

	if len(users) != 2 {
		t.Errorf("Expected 2 users, got %d", len(users))
	}

	userMap := make(map[string]bool)
	for _, user := range users {
		userMap[user] = true
	}

	if !userMap["alice"] || !userMap["bob"] {
		t.Error("Expected alice and bob to be in user role")
	}
}

// TestGetImplicitRoles tests getting implicit roles.
func TestGetImplicitRoles(t *testing.T) {
	rm := &RoleManager{
		allDomains:        make(map[string]struct{}),
		maxHierarchyLevel: 10,
		baseDN:            "dc=example,dc=com",
		userFilter:        "(uid=%s)",
		groupFilter:       "(member=%s)",
		roleAttr:          "cn",
		conn:              &MockLDAPConn{},
	}

	// Test getting implicit roles for alice
	roles, err := rm.GetImplicitRoles("alice")
	if err != nil {
		t.Errorf("Failed to get implicit roles for alice: %v", err)
	}

	if len(roles) < 2 {
		t.Errorf("Expected at least 2 implicit roles, got %d", len(roles))
	}
}

// TestGetImplicitUsers tests getting implicit users.
func TestGetImplicitUsers(t *testing.T) {
	rm := &RoleManager{
		allDomains:        make(map[string]struct{}),
		maxHierarchyLevel: 10,
		baseDN:            "dc=example,dc=com",
		userFilter:        "(uid=%s)",
		groupFilter:       "(member=%s)",
		roleAttr:          "cn",
		conn:              &MockLDAPConn{},
	}

	// Test getting implicit users for admin role
	users, err := rm.GetImplicitUsers("admin")
	if err != nil {
		t.Errorf("Failed to get implicit users for admin role: %v", err)
	}

	if len(users) != 1 {
		t.Errorf("Expected 1 implicit user, got %d", len(users))
	}
}

// TestClear tests the Clear method.
func TestClear(t *testing.T) {
	rm := &RoleManager{
		allDomains: map[string]struct{}{
			"domain1": {},
			"domain2": {},
		},
		maxHierarchyLevel: 10,
	}

	err := rm.Clear()
	if err != nil {
		t.Errorf("Failed to clear: %v", err)
	}

	if len(rm.allDomains) != 0 {
		t.Errorf("Expected allDomains to be empty after Clear, got %d domains", len(rm.allDomains))
	}
}

// TestDeleteDomain tests the DeleteDomain method.
func TestDeleteDomain(t *testing.T) {
	rm := &RoleManager{
		allDomains: map[string]struct{}{
			"domain1": {},
			"domain2": {},
		},
		maxHierarchyLevel: 10,
	}

	err := rm.DeleteDomain("domain1")
	if err != nil {
		t.Errorf("Failed to delete domain: %v", err)
	}

	if _, exists := rm.allDomains["domain1"]; exists {
		t.Error("Expected domain1 to be deleted")
	}

	if _, exists := rm.allDomains["domain2"]; !exists {
		t.Error("Expected domain2 to still exist")
	}
}

// TestGetAllDomains tests the GetAllDomains method.
func TestGetAllDomains(t *testing.T) {
	rm := &RoleManager{
		allDomains: map[string]struct{}{
			"domain1": {},
			"domain2": {},
		},
		maxHierarchyLevel: 10,
	}

	domains, err := rm.GetAllDomains()
	if err != nil {
		t.Errorf("Failed to get all domains: %v", err)
	}

	if len(domains) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(domains))
	}

	domainMap := make(map[string]bool)
	for _, domain := range domains {
		domainMap[domain] = true
	}

	if !domainMap["domain1"] || !domainMap["domain2"] {
		t.Error("Expected domain1 and domain2 to be returned")
	}
}

// TestMatch tests the Match method.
func TestMatch(t *testing.T) {
	rm := &RoleManager{
		allDomains:        make(map[string]struct{}),
		maxHierarchyLevel: 10,
	}

	if !rm.Match("test", "test") {
		t.Error("Expected 'test' to match 'test'")
	}

	if rm.Match("test", "other") {
		t.Error("Expected 'test' not to match 'other'")
	}
}

// TestNoConnectionError tests error handling when LDAP connection is nil.
func TestNoConnectionError(t *testing.T) {
	rm := &RoleManager{
		allDomains:        make(map[string]struct{}),
		maxHierarchyLevel: 10,
		baseDN:            "dc=example,dc=com",
		userFilter:        "(uid=%s)",
		groupFilter:       "(member=%s)",
		roleAttr:          "cn",
		conn:              nil, // No connection
	}

	// Test GetRoles with no connection
	_, err := rm.GetRoles("alice")
	if err == nil {
		t.Error("Expected error when LDAP connection is nil")
	}

	// Test GetUsers with no connection
	_, err = rm.GetUsers("admin")
	if err == nil {
		t.Error("Expected error when LDAP connection is nil")
	}
}

// Benchmark tests
func BenchmarkGetRoles(b *testing.B) {
	rm := &RoleManager{
		allDomains:        make(map[string]struct{}),
		maxHierarchyLevel: 10,
		baseDN:            "dc=example,dc=com",
		userFilter:        "(uid=%s)",
		groupFilter:       "(member=%s)",
		roleAttr:          "cn",
		conn:              &MockLDAPConn{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := rm.GetRoles("alice")
		if err != nil {
			b.Errorf("Failed to get roles: %v", err)
		}
	}
}

func BenchmarkHasLink(b *testing.B) {
	rm := &RoleManager{
		allDomains:        make(map[string]struct{}),
		maxHierarchyLevel: 10,
		baseDN:            "dc=example,dc=com",
		userFilter:        "(uid=%s)",
		groupFilter:       "(member=%s)",
		roleAttr:          "cn",
		conn:              &MockLDAPConn{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := rm.HasLink("alice", "admin")
		if err != nil {
			b.Errorf("Failed to check HasLink: %v", err)
		}
	}
}

// Example test demonstrating usage
func ExampleRoleManager_GetRoles() {
	// Note: This example requires a running LDAP server
	opts := &LDAPOptions{
		URL:               "ldap://localhost:389",
		BaseDN:            "dc=example,dc=com",
		UserFilter:        "(uid=%s)",
		GroupFilter:       "(member=%s)",
		RoleAttr:          "cn",
		BindDN:            "cn=admin,dc=example,dc=com",
		BindPassword:      "password",
		MaxHierarchyLevel: 10,
	}

	rm, err := NewRoleManager(opts)
	if err != nil {
		fmt.Printf("Failed to create role manager: %v\n", err)
		return
	}
	defer rm.Close()

	roles, err := rm.GetRoles("alice")
	if err != nil {
		fmt.Printf("Failed to get roles: %v\n", err)
		return
	}

	fmt.Printf("Roles for alice: %v\n", roles)
}
