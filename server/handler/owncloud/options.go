/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package owncloud

type Options struct {
	DSN string

	JoinUsername bool
	JoinUUID     bool

	BaseDN                  string
	AllowLocalAnonymousBind bool

	DefaultCompany    string
	DefaultMailDomain string
}
