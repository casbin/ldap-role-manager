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
	e, err := casbin.NewEnforcer("rbac_model.conf", "rbac_policy.csv")
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
	// In this example, we assume alice is in the admin group in LDAP
	// and bob is in the user group in LDAP
	
	// Alice (admin) can read and write data1
	if res, _ := e.Enforce("alice", "data1", "read"); res {
		fmt.Println("✓ alice can read data1")
	} else {
		fmt.Println("✗ alice cannot read data1")
	}

	if res, _ := e.Enforce("alice", "data1", "write"); res {
		fmt.Println("✓ alice can write data1")
	} else {
		fmt.Println("✗ alice cannot write data1")
	}

	// Bob (user) can read but not write data1
	if res, _ := e.Enforce("bob", "data1", "read"); res {
		fmt.Println("✓ bob can read data1")
	} else {
		fmt.Println("✗ bob cannot read data1")
	}

	if res, _ := e.Enforce("bob", "data1", "write"); res {
		fmt.Println("✓ bob can write data1")
	} else {
		fmt.Println("✗ bob cannot write data1")
	}

	// Get roles for alice
	roles, err := rm.GetRoles("alice")
	if err != nil {
		log.Printf("Failed to get roles for alice: %v", err)
	} else {
		fmt.Printf("\nRoles for alice: %v\n", roles)
	}

	// Get roles for bob
	roles, err = rm.GetRoles("bob")
	if err != nil {
		log.Printf("Failed to get roles for bob: %v", err)
	} else {
		fmt.Printf("Roles for bob: %v\n", roles)
	}
}
