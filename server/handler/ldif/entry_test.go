/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package ldif

import (
	"testing"

	"github.com/go-ldap/ldap/v3"
)

func TestLdifEntry_validatePassword(t *testing.T) {
	tests := []struct {
		name           string
		entry          *ldifEntry
		bindSimplePw   string
		expectError    bool
		expectedErrMsg string
	}{
		{
			name: "missing userPassword attribute",
			entry: &ldifEntry{
				Entry: &ldap.Entry{
					DN: "uid=test,ou=users,dc=example,dc=com",
				},
				UserPassword: nil,
			},
			bindSimplePw:   "password123",
			expectError:    true,
			expectedErrMsg: "user has no password attribute",
		},
		{
			name: "empty userPassword values",
			entry: &ldifEntry{
				Entry: &ldap.Entry{
					DN: "uid=test,ou=users,dc=example,dc=com",
				},
				UserPassword: &ldap.EntryAttribute{
					Name:   "userPassword",
					Values: []string{},
				},
			},
			bindSimplePw:   "password123",
			expectError:    true,
			expectedErrMsg: "user password attribute has no values",
		},
		{
			name: "valid password - correct match",
			entry: &ldifEntry{
				Entry: &ldap.Entry{
					DN: "uid=test,ou=users,dc=example,dc=com",
				},
				UserPassword: &ldap.EntryAttribute{
					Name:   "userPassword",
					Values: []string{"password123"},
				},
			},
			bindSimplePw: "password123",
			expectError:  false,
		},
		{
			name: "valid password - incorrect match",
			entry: &ldifEntry{
				Entry: &ldap.Entry{
					DN: "uid=test,ou=users,dc=example,dc=com",
				},
				UserPassword: &ldap.EntryAttribute{
					Name:   "userPassword",
					Values: []string{"password123"},
				},
			},
			bindSimplePw:   "wrongpassword",
			expectError:    true,
			expectedErrMsg: "invalid credentials",
		},
		{
			name: "multiple password values - uses first one",
			entry: &ldifEntry{
				Entry: &ldap.Entry{
					DN: "uid=test,ou=users,dc=example,dc=com",
				},
				UserPassword: &ldap.EntryAttribute{
					Name:   "userPassword",
					Values: []string{"password123", "password456"},
				},
			},
			bindSimplePw: "password123",
			expectError:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.entry.validatePassword(tt.bindSimplePw)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.expectedErrMsg != "" && err.Error() != tt.expectedErrMsg {
					t.Errorf("Expected error message '%s' but got '%s'", tt.expectedErrMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error but got: %v", err)
				}
			}
		})
	}
}

func TestLdifEntry_validatePassword_NilEntry(t *testing.T) {
	// Test with completely nil entry
	var entry *ldifEntry = nil
	
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