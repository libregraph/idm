/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ldif

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/go-asn1-ber/asn1-ber"

	"stash.kopano.io/kgol/kidm/internal/ldapserver"
)

func parseFilterToIndexFilter(filter string) ([][]string, error) {
	f, err := ldapserver.CompileFilter(filter)
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
	case ldapserver.FilterEqualityMatch:
		if len(f.Children) != 2 {
			return nil, errors.New("unsupported number of children in equality match filter")
		}
		attribute := f.Children[0].Value.(string)
		if !strings.EqualFold(attribute, "objectClass") {
			value := f.Children[1].Value.(string)
			parent = append(parent, []string{level, attribute, "eq", value})
		}

	case ldapserver.FilterPresent:
		if len(f.Children) != 0 {
			return nil, errors.New("unsupported number of children in presence match filter")
		}
		attribute := f.Data.String()
		if !strings.EqualFold(attribute, "objectClass") {
			parent = append(parent, []string{level, attribute, "pres", ""})
		}

	case ldapserver.FilterSubstrings:
		if len(f.Children) != 2 {
			return nil, errors.New("unsupported number of children in substrings filter")
		}
		attribute := f.Children[0].Value.(string)
		if !strings.EqualFold(attribute, "objectClass") {
			if len(f.Children[1].Children) != 1 {
				return nil, errors.New("unsupported number of children in substrings filter")
			}
			value := f.Children[1].Children[0].Value.(string)
			switch f.Children[1].Children[0].Tag {
			case ldapserver.FilterSubstringsInitial, ldapserver.FilterSubstringsAny, ldapserver.FilterSubstringsFinal:
				parent = append(parent, []string{level, attribute, "sub", value, strconv.FormatInt(int64(f.Children[1].Children[0].Tag), 10)})
			}
		}

	case ldapserver.FilterAnd:
		for idx, child := range f.Children {
			parent, err = parseFilterMatchLeavesForIndex(child, parent, fmt.Sprintf("%s.&%d", level, idx))
			if err != nil {
				return nil, err
			}
		}

	case ldapserver.FilterOr:
		for idx, child := range f.Children {
			parent, err = parseFilterMatchLeavesForIndex(child, parent, fmt.Sprintf("%s.|%d", level, idx))
			if err != nil {
				return nil, err
			}
		}

	case ldapserver.FilterNot:
		// Ignored for now.

	default:
	}

	return parent, nil
}
