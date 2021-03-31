/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ldif

import (
	"fmt"
	"os"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	nmcldap "github.com/nmcclain/ldap"
	"github.com/spacewander/go-suffix-tree"
)

// parseLDIFFile opens the named file for reading and parses it as LDIF.
func parseLDIFFile(fn string) (*ldif.LDIF, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}

	l := &ldif.LDIF{}
	err = ldif.Unmarshal(f, l)
	if err != nil {
		return nil, err
	}

	return l, nil
}

// treeFromLDIF makes a tree out of the provided LDIF and if index is not nil,
// also indexes each entry in the provided index.
func treeFromLDIF(l *ldif.LDIF, index Index) (*suffix.Tree, error) {
	t := suffix.NewTree()

	// NOTE(longsleep): Meh nmcldap vs goldap - for now create the type which we need to return for search.
	var entry *goldap.Entry
	for _, entry = range l.AllEntries() {
		e := &ldifEntry{
			Entry: &nmcldap.Entry{
				DN: strings.ToLower(entry.DN),
			},
		}
		for _, a := range entry.Attributes {
			switch strings.ToLower(a.Name) {
			case "userpassword":
				e.UserPassword = &nmcldap.EntryAttribute{
					Name:   a.Name,
					Values: a.Values,
				}
			default:
				e.Entry.Attributes = append(e.Entry.Attributes, &nmcldap.EntryAttribute{
					Name:   a.Name,
					Values: a.Values,
				})
			}
			if index != nil {
				// Index equality.
				index.Add(a.Name, "eq", a.Values, e)
			}
		}
		v, ok := t.Insert([]byte(e.DN), e)
		if !ok || v != nil {
			return nil, fmt.Errorf("duplicate value: %s", e.DN)
		}
	}

	return t, nil
}
