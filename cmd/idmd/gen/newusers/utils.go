/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 The LibreGraph Authors.
 */

package newusers

import (
	"regexp"
)

var emailRegex = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+\\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")

func isValidEmail(s string) bool {
	if len(s) < 3 && len(s) > 254 {
		return false
	}
	return emailRegex.MatchString(s)
}
