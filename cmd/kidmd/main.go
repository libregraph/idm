/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package main

import (
	"fmt"
	"os"

	"github.com/libregraph/idm/cmd"
	"github.com/libregraph/idm/cmd/kidmd/gen"
	"github.com/libregraph/idm/cmd/kidmd/serve"
)

func main() {
	cmd.RootCmd.Use = "kidmd"

	cmd.RootCmd.AddCommand(serve.CommandServe())
	cmd.RootCmd.AddCommand(gen.CommandGen())

	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
