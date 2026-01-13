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
	"testing"

	"github.com/casbin/casbin/v3/rbac"
)

func TestNewRoleManager(t *testing.T) {
	rm := NewRoleManager("localhost", 389)
	if rm == nil {
		t.Fatal("NewRoleManager returned nil")
	}
	if rm.host != "localhost" {
		t.Errorf("Expected host 'localhost', got '%s'", rm.host)
	}
	if rm.port != 389 {
		t.Errorf("Expected port 389, got %d", rm.port)
	}
	if rm.maxDepth != 10 {
		t.Errorf("Expected maxDepth 10, got %d", rm.maxDepth)
	}
}

func TestSetters(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	rm.SetBaseDN("dc=example,dc=com")
	if rm.baseDN != "dc=example,dc=com" {
		t.Errorf("Expected baseDN 'dc=example,dc=com', got '%s'", rm.baseDN)
	}

	rm.SetBindCredentials("cn=admin,dc=example,dc=com", "password")
	if rm.userDN != "cn=admin,dc=example,dc=com" {
		t.Errorf("Expected userDN 'cn=admin,dc=example,dc=com', got '%s'", rm.userDN)
	}
	if rm.password != "password" {
		t.Errorf("Expected password 'password', got '%s'", rm.password)
	}

	rm.SetUserFilter("(uid=%s)")
	if rm.userFilter != "(uid=%s)" {
		t.Errorf("Expected userFilter '(uid=%%s)', got '%s'", rm.userFilter)
	}

	rm.SetGroupFilter("(member=%s)")
	if rm.groupFilter != "(member=%s)" {
		t.Errorf("Expected groupFilter '(member=%%s)', got '%s'", rm.groupFilter)
	}

	rm.SetUserNameAttribute("username")
	if rm.userNameAttribute != "username" {
		t.Errorf("Expected userNameAttribute 'username', got '%s'", rm.userNameAttribute)
	}

	rm.SetGroupNameAttribute("groupname")
	if rm.groupNameAttribute != "groupname" {
		t.Errorf("Expected groupNameAttribute 'groupname', got '%s'", rm.groupNameAttribute)
	}

	rm.SetMemberAttribute("members")
	if rm.memberAttribute != "members" {
		t.Errorf("Expected memberAttribute 'members', got '%s'", rm.memberAttribute)
	}

	rm.SetMaxDepth(20)
	if rm.maxDepth != 20 {
		t.Errorf("Expected maxDepth 20, got %d", rm.maxDepth)
	}
}

func TestClear(t *testing.T) {
	rm := NewRoleManager("localhost", 389)
	rm.allDomains = []string{"domain1", "domain2"}
	rm.hasPolicyDomains = map[string]bool{"domain1": true}

	err := rm.Clear()
	if err != nil {
		t.Errorf("Clear returned error: %v", err)
	}

	if len(rm.allDomains) != 0 {
		t.Errorf("Expected allDomains to be empty, got %v", rm.allDomains)
	}

	if len(rm.hasPolicyDomains) != 0 {
		t.Errorf("Expected hasPolicyDomains to be empty, got %v", rm.hasPolicyDomains)
	}
}

func TestAddLink(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	// AddLink should be a no-op for LDAP role manager
	err := rm.AddLink("user1", "role1")
	if err != nil {
		t.Errorf("AddLink returned error: %v", err)
	}

	err = rm.AddLink("user2", "role2", "domain1")
	if err != nil {
		t.Errorf("AddLink with domain returned error: %v", err)
	}
}

func TestDeleteLink(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	// DeleteLink should be a no-op for LDAP role manager
	err := rm.DeleteLink("user1", "role1")
	if err != nil {
		t.Errorf("DeleteLink returned error: %v", err)
	}

	err = rm.DeleteLink("user2", "role2", "domain1")
	if err != nil {
		t.Errorf("DeleteLink with domain returned error: %v", err)
	}
}

func TestBuildRelationship(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	// BuildRelationship is deprecated and should be a no-op
	err := rm.BuildRelationship("user1", "role1")
	if err != nil {
		t.Errorf("BuildRelationship returned error: %v", err)
	}
}

func TestMatch(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	// Test default matching (exact match)
	if !rm.Match("test", "test") {
		t.Error("Expected Match('test', 'test') to return true")
	}

	if rm.Match("test1", "test2") {
		t.Error("Expected Match('test1', 'test2') to return false")
	}

	// Test custom matching function
	rm.AddMatchingFunc("custom", func(arg1, arg2 string) bool {
		return len(arg1) == len(arg2)
	})

	if !rm.Match("abc", "def") {
		t.Error("Expected custom Match('abc', 'def') to return true (same length)")
	}

	if rm.Match("ab", "abc") {
		t.Error("Expected custom Match('ab', 'abc') to return false (different length)")
	}
}

func TestAddMatchingFunc(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	called := false
	matchFunc := func(arg1, arg2 string) bool {
		called = true
		return arg1 == arg2
	}

	rm.AddMatchingFunc("test", matchFunc)

	if rm.matchingFunc == nil {
		t.Error("Expected matchingFunc to be set")
	}

	// Test that the function works
	result := rm.Match("test", "test")
	if !called {
		t.Error("Expected matching function to be called")
	}
	if !result {
		t.Error("Expected Match to return true")
	}
}

func TestAddDomainMatchingFunc(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	matchFunc := func(arg1, arg2 string) bool {
		return arg1 == arg2
	}

	rm.AddDomainMatchingFunc("test", matchFunc)

	if rm.domainMatchingFunc == nil {
		t.Error("Expected domainMatchingFunc to be set")
	}
}

func TestDeleteDomain(t *testing.T) {
	rm := NewRoleManager("localhost", 389)
	rm.allDomains = []string{"domain1", "domain2", "domain3"}
	rm.hasPolicyDomains = map[string]bool{"domain1": true, "domain2": true}

	err := rm.DeleteDomain("domain2")
	if err != nil {
		t.Errorf("DeleteDomain returned error: %v", err)
	}

	if len(rm.allDomains) != 2 {
		t.Errorf("Expected 2 domains remaining, got %d", len(rm.allDomains))
	}

	for _, d := range rm.allDomains {
		if d == "domain2" {
			t.Error("Expected domain2 to be removed from allDomains")
		}
	}

	if rm.hasPolicyDomains["domain2"] {
		t.Error("Expected domain2 to be removed from hasPolicyDomains")
	}

	if !rm.hasPolicyDomains["domain1"] {
		t.Error("Expected domain1 to still be in hasPolicyDomains")
	}
}

func TestGetAllDomains(t *testing.T) {
	rm := NewRoleManager("localhost", 389)
	rm.allDomains = []string{"domain1", "domain2"}

	domains, err := rm.GetAllDomains()
	if err != nil {
		t.Errorf("GetAllDomains returned error: %v", err)
	}

	if len(domains) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(domains))
	}
}

func TestGetDomains(t *testing.T) {
	rm := NewRoleManager("localhost", 389)
	rm.allDomains = []string{"domain1", "domain2"}

	domains, err := rm.GetDomains("user1")
	if err != nil {
		t.Errorf("GetDomains returned error: %v", err)
	}

	if len(domains) != 2 {
		t.Errorf("Expected 2 domains, got %d", len(domains))
	}
}

func TestPrintRoles(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	// PrintRoles should be a no-op for LDAP role manager
	err := rm.PrintRoles()
	if err != nil {
		t.Errorf("PrintRoles returned error: %v", err)
	}
}

func TestHasLinkNoConnection(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	// Should return error when not connected
	_, err := rm.HasLink("user1", "role1")
	if err == nil {
		t.Error("Expected HasLink to return error when not connected")
	}
}

func TestGetRolesNoConnection(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	// Should return error when not connected
	_, err := rm.GetRoles("user1")
	if err == nil {
		t.Error("Expected GetRoles to return error when not connected")
	}
}

func TestGetUsersNoConnection(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	// Should return error when not connected
	_, err := rm.GetUsers("role1")
	if err == nil {
		t.Error("Expected GetUsers to return error when not connected")
	}
}

func TestGetImplicitRolesNoConnection(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	// Should return error when not connected
	_, err := rm.GetImplicitRoles("user1")
	if err == nil {
		t.Error("Expected GetImplicitRoles to return error when not connected")
	}
}

func TestGetImplicitUsersNoConnection(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	// Should return error when not connected
	_, err := rm.GetImplicitUsers("role1")
	if err == nil {
		t.Error("Expected GetImplicitUsers to return error when not connected")
	}
}

func TestRoleManagerInterface(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	// Verify that RoleManager implements the rbac.RoleManager interface
	var _ rbac.RoleManager = rm
}

func TestClose(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	// Should not error even if not connected
	err := rm.Close()
	if err != nil {
		t.Errorf("Close returned error: %v", err)
	}
}

func TestConcurrentAccess(t *testing.T) {
	rm := NewRoleManager("localhost", 389)

	// Test concurrent reads
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			rm.Match("test", "test")
			domains, _ := rm.GetAllDomains()
			_ = domains
			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}

	// Test concurrent writes
	done2 := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func(idx int) {
			rm.SetMaxDepth(idx)
			rm.AddLink("user", "role")
			rm.DeleteLink("user", "role")
			done2 <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done2
	}
}
