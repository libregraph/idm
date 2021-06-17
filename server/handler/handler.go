/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 The LibreGraph Authors.
 */

package handler

import (
	"context"

	"github.com/libregraph/idm/pkg/ldapserver"
)

// Interface for handlers.
type Handler interface {
	ldapserver.Binder
	ldapserver.Searcher
	ldapserver.Closer

	WithContext(context.Context) Handler
	Reload(context.Context) error
}

// Interface for middlewares.
type Middleware interface {
	WithHandler(next Handler) Handler
}
