/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/libregraph/idm/version"
)

// CommandVersion provides the commandline implementation for version.
func CommandVersion() *cobra.Command {
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the version and exit",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf(`Version    : %s
Build date : %s
Built with : %s %s/%s
`,
				version.Version, version.BuildDate, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		},
	}

	return versionCmd
}

func init() {
	RootCmd.AddCommand(CommandVersion())
}
