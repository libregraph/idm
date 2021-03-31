/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ldif

import (
	"strings"
)

var indexAttributes = map[string]string{
	"entryCSN":     "eq",
	"entryUUID":    "eq",
	"objectClass":  "eq",
	"cn":           "pres,eq,sub",
	"gidNumber":    "eq",
	"mail":         "eq",
	"memberUid":    "eq",
	"ou":           "eq",
	"uid":          "eq",
	"uidNumber":    "eq",
	"uniqueMember": "eq",

	"kopanoAccount":       "eq",
	"kopanoAliases":       "eq",
	"kopanoViewPrivilege": "eq",

	"sn":        "pres,eq,sub",
	"givenName": "pres,eq,sub",
}

type indexMap map[string][]*ldifEntry

func newIndexMap() indexMap {
	return make(indexMap)
}

type indexMapRegister map[string]indexMap

func newIndexMapRegister() indexMapRegister {
	imr := make(indexMapRegister)
	for name, ops := range indexAttributes {
		switch name {
		case "objectClass":
			// Don't index objectClass, make no sense since everything has it.
		default:
			for _, op := range strings.Split(ops, ",") {
				imr[imr.getKey(name, op)] = newIndexMap()
			}
		}
	}
	return imr
}

func (imr indexMapRegister) getKey(name, op string) string {
	return strings.ToLower(name) + "," + op
}

func (imr indexMapRegister) add(name, op string, values []string, entry *ldifEntry) bool {
	index, ok := imr[imr.getKey(name, op)]
	if !ok {
		return false
	}
	for _, value := range values {
		value = strings.ToLower(value)
		index[value] = append(index[value], entry)
	}
	return true
}

func (imr indexMapRegister) load(name, op, value string) ([]*ldifEntry, bool) {
	index, ok := imr[imr.getKey(name, op)]
	if !ok {
		return nil, false
	}
	values, ok := index[strings.ToLower(value)]
	return values, ok
}
