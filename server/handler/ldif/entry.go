/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package ldif

import (
	"fmt"

	"github.com/go-ldap/ldap/v3"

	"github.com/libregraph/idm/pkg/ldappassword"
)

type ldifEntry struct {
	*ldap.Entry

	UserPassword *ldap.EntryAttribute
}

func (entry *ldifEntry) validatePassword(bindSimplePw string) error {
	// Check if UserPassword attribute exists
	if entry.UserPassword == nil {
		return fmt.Errorf("user has no password attribute")
	}
	
	// Check if password values exist
	if len(entry.UserPassword.Values) == 0 {
		return fmt.Errorf("user password attribute has no values")
	}
	
	// Existing validation logic
	match, err := ldappassword.Validate(bindSimplePw, entry.UserPassword.Values[0])
	if err != nil {
		return err
	}
	if !match {
		return fmt.Errorf("invalid credentials")
	}
	return nil
}
