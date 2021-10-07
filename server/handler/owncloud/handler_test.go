/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package owncloud

import (
	"bytes"
	"testing"

	// Provides mysql drivers
	ber "github.com/go-asn1-ber/asn1-ber"
	_ "github.com/go-sql-driver/mysql"
	"github.com/libregraph/idm/pkg/ldapserver"
)

// new returns a dummy auth manager for testing
func newDummy(joinUsername, joinUUID bool) (*ocHandler, error) {
	h := &ocHandler{
		options: &Options{
			JoinUsername: joinUsername,
			JoinUUID:     joinUUID,
		},
	}

	return h, nil
}

func TestHandler(t *testing.T) {
	tests := map[string]struct {
		f              *ber.Packet
		sql            string
		expectedsql    string
		expectedvalues []string
	}{
		// Bogus values
		"bogus-1": {&ber.Packet{}, "", "", []string{}},

		// eq matches
		"eq": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterEqualityMatch},
			Children:   []*ber.Packet{{Value: "mail"}, {Value: "bar"}},
		}, "", "email=?", []string{"bar"}},

		// present matches
		"present": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterPresent},
			Data:       bytes.NewBufferString("mail"),
		}, "", "email IS NOT NULL", []string{}},

		// AND
		"and": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterAnd},
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: ldapserver.FilterEqualityMatch},
					Children:   []*ber.Packet{{Value: "mail"}, {Value: "bar"}},
				}, {
					Identifier: ber.Identifier{Tag: ldapserver.FilterEqualityMatch},
					Children:   []*ber.Packet{{Value: "cn"}, {Value: "bar"}},
				}},
		}, "", "(email=? AND display_name=?)", []string{"bar", "bar"}},

		// OR
		"or": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterOr},
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: ldapserver.FilterEqualityMatch},
					Children:   []*ber.Packet{{Value: "ownclouduuid"}, {Value: "bar"}},
				}, {
					Identifier: ber.Identifier{Tag: ldapserver.FilterEqualityMatch},
					Children:   []*ber.Packet{{Value: "uid"}, {Value: "bar"}},
				}},
		}, "", "(user_id=? OR lower_user_id=?)", []string{"bar", "bar"}},

		// NOT
		"not": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterNot},
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: ldapserver.FilterEqualityMatch},
					Children:   []*ber.Packet{{Value: "cn"}, {Value: "bar"}},
				}},
		}, "", "NOT display_name=?", []string{"bar"}},

		// substring / LIKE
		"substring-initial": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterSubstrings},
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: ber.TagOctetString},
					Value:      "mail",
				}, {
					Identifier: ber.Identifier{Tag: ldapserver.FilterSubstringsInitial},
					Children:   []*ber.Packet{{Value: "foo"}},
				}},
		}, "", "email LIKE ?", []string{"foo%"}},
		"substring-any": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterSubstrings},
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: ber.TagOctetString},
					Value:      "mail",
				}, {
					Identifier: ber.Identifier{Tag: ber.TagSequence},
					Children:   []*ber.Packet{{Identifier: ber.Identifier{Tag: ldapserver.FilterSubstringsAny}, Value: "foo"}},
				}},
		}, "", "email LIKE ?", []string{"%foo%"}},
		"substring-final": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterSubstrings},
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: ber.TagOctetString},
					Value:      "mail",
				}, {
					Identifier: ber.Identifier{Tag: ber.TagSequence},
					Children:   []*ber.Packet{{Identifier: ber.Identifier{Tag: ldapserver.FilterSubstringsFinal}, Value: "foo"}},
				}},
		}, "", "email LIKE ?", []string{"%foo"}},
	}

	h, err := newDummy(false, false)
	if err != nil {
		t.Fatalf("could not initialize owncloudsql auth manager: %v", err)
	}

	for name := range tests {
		var tc = tests[name]
		t.Run(name, func(t *testing.T) {
			_, actualsql, actualvalues, err := h.parseFilterMatchLeavesForSQLFragments(tc.f, tc.sql)
			if err != nil {
				t.Fatalf("%v %v", t.Name(), err)
			}
			if actualsql != tc.expectedsql {
				t.Fatalf("%v returned wrong sql:\n\tAct: %v\n\tExp: %v", t.Name(), actualsql, tc.expectedsql)
			}
			if len(actualvalues) != len(tc.expectedvalues) {
				t.Fatalf("%v returned wrong number of values :\n\tAct: %v\n\tExp: %v", t.Name(), actualvalues, tc.expectedvalues)
			}
			for i := range tc.expectedvalues {
				if actualvalues[i] != tc.expectedvalues[i] {
					t.Fatalf("%v returned wrong values:\n\tAct: %v\n\tExp: %v", t.Name(), actualvalues, tc.expectedvalues)
				}
			}
		})
	}
}

func TestHandlerWithJoin(t *testing.T) {
	tests := map[string]struct {
		f              *ber.Packet
		sql            string
		expectedsql    string
		expectedvalues []string
	}{
		// Bogus values
		"bogus-1": {&ber.Packet{}, "", "", []string{}},

		// eq matches
		"eq": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterEqualityMatch},
			Children:   []*ber.Packet{{Value: "mail"}, {Value: "bar"}},
		}, "", "email=?", []string{"bar"}},

		// present matches
		"present": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterPresent},
			Data:       bytes.NewBufferString("mail"),
		}, "", "email IS NOT NULL", []string{}},

		// AND
		"and": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterAnd},
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: ldapserver.FilterEqualityMatch},
					Children:   []*ber.Packet{{Value: "mail"}, {Value: "bar"}},
				}, {
					Identifier: ber.Identifier{Tag: ldapserver.FilterEqualityMatch},
					Children:   []*ber.Packet{{Value: "cn"}, {Value: "bar"}},
				}},
		}, "", "(email=? AND display_name=?)", []string{"bar", "bar"}},

		// OR
		"or": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterOr},
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: ldapserver.FilterEqualityMatch},
					Children:   []*ber.Packet{{Value: "ownclouduuid"}, {Value: "bar"}},
				}, {
					Identifier: ber.Identifier{Tag: ldapserver.FilterEqualityMatch},
					Children:   []*ber.Packet{{Value: "uid"}, {Value: "bar"}},
				}},
		}, "", "(p.configvalue=? OR p2.configvalue=?)", []string{"bar", "bar"}},

		// NOT
		"not": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterNot},
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: ldapserver.FilterEqualityMatch},
					Children:   []*ber.Packet{{Value: "cn"}, {Value: "bar"}},
				}},
		}, "", "NOT display_name=?", []string{"bar"}},

		// substring / LIKE
		"substring-initial": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterSubstrings},
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: ber.TagOctetString},
					Value:      "mail",
				}, {
					Identifier: ber.Identifier{Tag: ldapserver.FilterSubstringsInitial},
					Children:   []*ber.Packet{{Value: "foo"}},
				}},
		}, "", "email LIKE ?", []string{"foo%"}},
		"substring-any": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterSubstrings},
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: ber.TagOctetString},
					Value:      "mail",
				}, {
					Identifier: ber.Identifier{Tag: ber.TagSequence},
					Children:   []*ber.Packet{{Identifier: ber.Identifier{Tag: ldapserver.FilterSubstringsAny}, Value: "foo"}},
				}},
		}, "", "email LIKE ?", []string{"%foo%"}},
		"substring-final": {&ber.Packet{
			Identifier: ber.Identifier{Tag: ldapserver.FilterSubstrings},
			Children: []*ber.Packet{
				{
					Identifier: ber.Identifier{Tag: ber.TagOctetString},
					Value:      "mail",
				}, {
					Identifier: ber.Identifier{Tag: ber.TagSequence},
					Children:   []*ber.Packet{{Identifier: ber.Identifier{Tag: ldapserver.FilterSubstringsFinal}, Value: "foo"}},
				}},
		}, "", "email LIKE ?", []string{"%foo"}},
	}

	h, err := newDummy(true, true)
	if err != nil {
		t.Fatalf("could not initialize owncloudsql auth manager: %v", err)
	}

	for name := range tests {
		var tc = tests[name]
		t.Run(name, func(t *testing.T) {
			_, actualsql, actualvalues, err := h.parseFilterMatchLeavesForSQLFragments(tc.f, tc.sql)
			if err != nil {
				t.Fatalf("%v %v", t.Name(), err)
			}
			if actualsql != tc.expectedsql {
				t.Fatalf("%v returned wrong sql:\n\tAct: %v\n\tExp: %v", t.Name(), actualsql, tc.expectedsql)
			}
			if len(actualvalues) != len(tc.expectedvalues) {
				t.Fatalf("%v returned wrong number of values :\n\tAct: %v\n\tExp: %v", t.Name(), actualvalues, tc.expectedvalues)
			}
			for i := range tc.expectedvalues {
				if actualvalues[i] != tc.expectedvalues[i] {
					t.Fatalf("%v returned wrong values:\n\tAct: %v\n\tExp: %v", t.Name(), actualvalues, tc.expectedvalues)
				}
			}
		})
	}
}
