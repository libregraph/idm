/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package passwd

import (
	"errors"

	"github.com/Songmu/prompter"
)

func promptForPassword() (string, error) {
	password := (&prompter.Prompter{
		Message:    "New password",
		UseDefault: false,
		NoEcho:     true,
	}).Prompt()

	confirm := (&prompter.Prompter{
		Message:    "Re-enter new password",
		UseDefault: false,
		NoEcho:     true,
	}).Prompt()

	if password != confirm || password == "" {
		return "", errors.New("password verification failed")
	}

	return password, nil
}
