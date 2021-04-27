/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ldif

import (
	"github.com/go-ldap/ldif"
	"github.com/spacewander/go-suffix-tree"
)

type ldifMemoryValue struct {
	l *ldif.LDIF
	t *suffix.Tree

	index Index
}
