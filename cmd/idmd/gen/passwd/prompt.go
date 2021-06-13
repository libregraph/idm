/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
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
