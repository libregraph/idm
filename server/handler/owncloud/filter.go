/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package owncloud

import (
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/pkg/errors"

	"github.com/libregraph/idm/pkg/ldapserver"

	// Provides mysql drivers
	_ "github.com/go-sql-driver/mysql"
)

func (h *ocHandler) parseFilterToSQLFragments(filter string) ([]string, string, []interface{}, error) {
	f, err := ldapserver.CompileFilter(filter)
	if err != nil {
		return nil, "", nil, err
	}

	return h.parseFilterMatchLeavesForSQLFragments(f, "")
}
func (h *ocHandler) parseFilterMatchLeavesForSQLFragments(f *ber.Packet, wheresql string) ([]string, string, []interface{}, error) {

	values := []interface{}{}
	objectclasses := []string{}

	switch f.Tag {
	case ldapserver.FilterEqualityMatch:
		if len(f.Children) != 2 {
			return nil, "", nil, errors.New("unsupported number of children in equality match filter")
		}
		column := h.columnForAttribute(f.Children[0].Value.(string))
		if column == "" && strings.ToLower(f.Children[0].Value.(string)) == "objectclass" {
			objectclasses = append(objectclasses, f.Children[1].Value.(string))
		} else if column != "" {
			wheresql += column + "=?"
			values = append(values, f.Children[1].Value.(string))
		}

	case ldapserver.FilterPresent:
		if len(f.Children) != 0 {
			return nil, "", nil, errors.New("unsupported number of children in presence match filter")
		}
		attribute := f.Data.String()
		column := h.columnForAttribute(attribute)
		if column != "" {
			wheresql += column + " IS NOT NULL"
		}

	case ldapserver.FilterSubstrings:
		if len(f.Children) != 2 {
			return nil, "", nil, errors.New("unsupported number of children in substrings filter")
		}
		attribute := f.Children[0].Value.(string)
		if len(f.Children[1].Children) != 1 {
			return nil, "", nil, errors.New("unsupported number of children in substrings filter")
		}
		value := sanitizeWildcards(f.Children[1].Children[0].Value.(string))
		column := h.columnForAttribute(attribute)
		if column != "" {
			wheresql += column + " LIKE ?"
			switch f.Children[1].Children[0].Tag {
			case ldapserver.FilterSubstringsInitial:
				value += "%"
			case ldapserver.FilterSubstringsAny:
				value = "%" + value + "%"
			case ldapserver.FilterSubstringsFinal:
				value = "%" + value
			}
			values = append(values, value)
		}

	case ldapserver.FilterAnd:
		conditions := []string{}
		for i := range f.Children {
			oc, condition, v, err := h.parseFilterMatchLeavesForSQLFragments(f.Children[i], wheresql)
			if err != nil {
				return nil, "", nil, err
			}
			objectclasses = append(objectclasses, oc...)
			if condition != "" {
				conditions = append(conditions, condition)
				values = append(values, v...)
			}
		}
		if len(conditions) > 0 {
			wheresql += "(" + strings.Join(conditions, " AND ") + ")"
		}
	case ldapserver.FilterOr:
		conditions := []string{}
		for i := range f.Children {
			oc, condition, v, err := h.parseFilterMatchLeavesForSQLFragments(f.Children[i], wheresql)
			if err != nil {
				return nil, "", nil, err
			}
			objectclasses = append(objectclasses, oc...)
			if condition != "" {
				conditions = append(conditions, condition)
				values = append(values, v...)
			}
		}
		if len(conditions) > 0 {
			wheresql += "(" + strings.Join(conditions, " OR ") + ")"
		}

	case ldapserver.FilterNot:
		if len(f.Children) != 1 {
			return nil, "", nil, errors.New("unsupported number of children in not filter")
		}
		oc, condition, cvalues, err := h.parseFilterMatchLeavesForSQLFragments(f.Children[0], wheresql)
		if err != nil {
			return nil, "", nil, err
		}
		objectclasses = append(objectclasses, oc...)
		values = append(values, cvalues...)
		wheresql += "NOT " + condition

	default:
		return nil, "", values, fmt.Errorf("search error: unsupported tag '%s' in filter", f.Description)
	}
	return objectclasses, wheresql, values, nil
}

func (h *ocHandler) columnForAttribute(a string) string {
	switch strings.ToLower(a) {
	case "mail":
		return "email"
	case "cn":
		return "display_name"
	case "ownclouduuid":
		if h.options.JoinUsername {
			return "p.configvalue"
		} else {
			return "user_id"
		}
	case "uid":
		if h.options.JoinUsername {
			return "p2.configvalue"
		} else {
			return "lower_user_id"
		}
	default:
		return ""
	}
}

func sanitizeWildcards(q string) string {
	return strings.ReplaceAll(strings.ReplaceAll(q, "%", `\%`), "_", `\_`)
}
