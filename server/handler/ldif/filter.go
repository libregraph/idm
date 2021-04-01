/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ldif

import (
	"errors"
	"fmt"
	"strings"

	"github.com/go-asn1-ber/asn1-ber"
	nmcldap "github.com/nmcclain/ldap"
)

func parseFilterToIndexFilter(filter string) ([][]string, error) {
	f, err := nmcldap.CompileFilter(filter)
	if err != nil {
		return nil, err
	}

	var result [][]string
	matches, err := parseFilterMatchLeavesForIndex(f, nil, "")
	if err != nil {
		return nil, fmt.Errorf("parse filter for index failed: %w", err)
	} else {
		for _, f := range matches {
			result = append(result, f[1:])
		}
	}
	return result, err
}

func parseFilterMatchLeavesForIndex(f *ber.Packet, parent [][]string, level string) ([][]string, error) {
	var err error

	if parent == nil {
		parent = make([][]string, 0)
	}

	switch f.Tag {
	case nmcldap.FilterEqualityMatch:
		if len(f.Children) != 2 {
			return nil, errors.New("unsupported number of children in equality match filter")
		}
		switch attribute := strings.ToLower(f.Children[0].Value.(string)); attribute {
		case "objectclass":
			// Ignore objectClass - makes no sense to index as et would index everything.
		default:
			value := f.Children[1].Value.(string)
			parent = append(parent, []string{level, attribute, "eq", value})
		}

	case nmcldap.FilterAnd:
		for idx, child := range f.Children {
			parent, err = parseFilterMatchLeavesForIndex(child, parent, fmt.Sprintf("%s.&%d", level, idx))
			if err != nil {
				return nil, err
			}
		}

	case nmcldap.FilterOr:
		for idx, child := range f.Children {
			parent, err = parseFilterMatchLeavesForIndex(child, parent, fmt.Sprintf("%s.|%d", level, idx))
			if err != nil {
				return nil, err
			}
		}

	case nmcldap.FilterNot, nmcldap.FilterPresent:
		// Ignored for now.

	default:
	}

	return parent, nil
}
