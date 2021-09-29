/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package gen

import (
	"github.com/spf13/cobra"

	"github.com/libregraph/idm/cmd/idmd/gen/newusers"
	"github.com/libregraph/idm/cmd/idmd/gen/passwd"
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
