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

// +build example

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

	// Optional: Customize filters and attributes
	rm.SetUserFilter("(&(objectClass=person)(uid=%s))")
	rm.SetGroupFilter("(&(objectClass=groupOfNames)(member=%s))")
	rm.SetUserNameAttribute("uid")
	rm.SetGroupNameAttribute("cn")

	// Connect to LDAP server
	err := rm.Connect()
	if err != nil {
		log.Fatalf("Failed to connect to LDAP: %v", err)
	}
	defer rm.Close()

	// Create a Casbin enforcer with model and policy files
	// Model file (model.conf) should contain RBAC model definition
	// Policy file (policy.csv) should contain authorization policies
	e, err := casbin.NewEnforcer("model.conf", "policy.csv")
	if err != nil {
		log.Fatalf("Failed to create enforcer: %v", err)
	}

	// Set the LDAP role manager
	e.SetRoleManager(rm)

	// Load the policy from file
	err = e.LoadPolicy()
	if err != nil {
		log.Fatalf("Failed to load policy: %v", err)
	}

	// Example: Check if alice can read data1
	if ok, err := e.Enforce("alice", "data1", "read"); err != nil {
		log.Fatalf("Enforce failed: %v", err)
	} else if ok {
		log.Println("alice can read data1")
	} else {
		log.Println("alice cannot read data1")
	}

	// Example: Check roles for a user
	roles, err := rm.GetRoles("alice")
	if err != nil {
		log.Fatalf("Failed to get roles: %v", err)
	}
	log.Printf("Roles for alice: %v\n", roles)
}
