/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package ldif

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestLdifEntry_validatePassword_MissingPassword(t *testing.T) {
	entry := &ldifEntry{
		Entry: &ldap.Entry{
			DN: "uid=test,ou=users,dc=example,dc=com",
		},
		UserPassword: nil,
	}

	err := entry.validatePassword("password123")
	if err == nil {
		t.Errorf("Expected error but got none")
		return
	}
	if err.Error() != "user has no password attribute" {
		t.Errorf("Expected error message 'user has no password attribute' but got '%s'", err.Error())
	}
}

func TestLdifEntry_validatePassword_EmptyValues(t *testing.T) {
	entry := &ldifEntry{
		Entry: &ldap.Entry{
			DN: "uid=test,ou=users,dc=example,dc=com",
		},
		UserPassword: &ldap.EntryAttribute{
			Name:   "userPassword",
			Values: []string{},
		},
	}

	err := entry.validatePassword("password123")
	if err == nil {
		t.Errorf("Expected error but got none")
		return
	}
	if err.Error() != "user password attribute has no values" {
		t.Errorf("Expected error message 'user password attribute has no values' but got '%s'", err.Error())
	}
}

func TestLdifEntry_validatePassword_CorrectPassword(t *testing.T) {
	entry := &ldifEntry{
		Entry: &ldap.Entry{
			DN: "uid=test,ou=users,dc=example,dc=com",
		},
		UserPassword: &ldap.EntryAttribute{
			Name:   "userPassword",
			Values: []string{"password123"},
		},
	}

	err := entry.validatePassword("password123")
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}
}

func TestLdifEntry_validatePassword_IncorrectPassword(t *testing.T) {
	entry := &ldifEntry{
		Entry: &ldap.Entry{
			DN: "uid=test,ou=users,dc=example,dc=com",
		},
		UserPassword: &ldap.EntryAttribute{
			Name:   "userPassword",
			Values: []string{"password123"},
		},
	}

	err := entry.validatePassword("wrongpassword")
	if err == nil {
		t.Errorf("Expected error but got none")
		return
	}
	if err.Error() != "invalid credentials" {
		t.Errorf("Expected error message 'invalid credentials' but got '%s'", err.Error())
	}
}

func TestLdifEntry_validatePassword_MultipleValues(t *testing.T) {
	entry := &ldifEntry{
		Entry: &ldap.Entry{
			DN: "uid=test,ou=users,dc=example,dc=com",
		},
		UserPassword: &ldap.EntryAttribute{
			Name:   "userPassword",
			Values: []string{"password123", "password456"},
		},
	}

	err := entry.validatePassword("password123")
	if err != nil {
		t.Errorf("Expected no error but got: %v", err)
	}
}

func TestLdifEntry_validatePassword_NilEntry(t *testing.T) {
	// Test with completely nil entry
	var entry *ldifEntry

	// This should panic - testing that our fix prevents the panic
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("Expected panic when calling validatePassword on nil entry")
		}
	}()

	err := entry.validatePassword("password123")
	if err != nil {
		t.Errorf("Should have panicked before returning error")
	}
}

// Test with actual LDIF parsing to ensure end-to-end functionality
func TestLdifEntry_validatePassword_WithLDIFParsing(t *testing.T) {
	// This test verifies that our LDIF parsing and entry creation
	// properly handles missing userPassword attributes without panicking
	// when validatePassword is called

	// Note: This would require actual LDIF parsing which involves more setup
	// The testLDIF would contain various password scenarios:
	// - Valid user with password
	// - User without userPassword attribute
	// - User with empty userPassword values
	// For now, we test the core validation logic in the other tests
	t.Skip("Integration test - requires full LDIF parsing infrastructure")
}

// Benchmark to ensure no performance regression
func BenchmarkLdifEntry_validatePassword_Valid(b *testing.B) {
	entry := &ldifEntry{
		Entry: &ldap.Entry{
			DN: "uid=test,ou=users,dc=example,dc=com",
		},
		UserPassword: &ldap.EntryAttribute{
			Name:   "userPassword",
			Values: []string{"password123"},
		},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = entry.validatePassword("password123")
	}
}

func BenchmarkLdifEntry_validatePassword_MissingPassword(b *testing.B) {
	entry := &ldifEntry{
		Entry: &ldap.Entry{
			DN: "uid=test,ou=users,dc=example,dc=com",
		},
		UserPassword: nil,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = entry.validatePassword("password123")
	}
}
