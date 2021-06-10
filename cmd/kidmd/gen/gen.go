/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package gen

import (
	"github.com/spf13/cobra"

	"github.com/libregraph/idm/cmd/kidmd/gen/newusers"
	"github.com/libregraph/idm/cmd/kidmd/gen/passwd"
)

func CommandGen() *cobra.Command {
	genCmd := &cobra.Command{
		Use:   "gen [...args]",
		Short: "A collection of useful generators",
	}

	genCmd.AddCommand(newusers.CommandNewusers())
	genCmd.AddCommand(passwd.CommandPasswd())

	return genCmd
}
