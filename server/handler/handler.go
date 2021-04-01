/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package handler

import (
	nmcldap "github.com/nmcclain/ldap"
)

// Interface for handlers.
type Handler interface {
	nmcldap.Binder
	nmcldap.Searcher
	nmcldap.Closer
}

// Interface for middlewares.
type Middleware interface {
	WithHandler(next Handler) Handler
}
