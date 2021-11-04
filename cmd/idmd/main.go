/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package main

import (
	"fmt"
	"os"

	"github.com/libregraph/idm/cmd"
	"github.com/libregraph/idm/cmd/idmd/boltdb"
	"github.com/libregraph/idm/cmd/idmd/gen"
	"github.com/libregraph/idm/cmd/idmd/serve"
)

func main() {
	cmd.RootCmd.Use = "idmd"

	cmd.RootCmd.AddCommand(serve.CommandServe())
	cmd.RootCmd.AddCommand(gen.CommandGen())
	cmd.RootCmd.AddCommand(boltdb.CommandBoltDB())
	if err := cmd.RootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}
}
