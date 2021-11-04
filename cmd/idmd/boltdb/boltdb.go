/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package boltdb

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/libregraph/idm/cmd/idmd/boltdb/load"
)

var (
	BoltDBFile string
	LDAPBaseDN string
	LogLevel   string
	InputFile  string
)

func CommandBoltDB() *cobra.Command {
	boltdbCmd := &cobra.Command{
		Use:   "boltdb [...args]",
		Short: "Utility commands related to the BoltDB Database Handler",
	}

	boltdbCmd.PersistentFlags().StringVar(&LogLevel, "log-level", LogLevel, "Log level (one of panic, fatal, error, warn, info or debug)")
	boltdbCmd.PersistentFlags().StringVar(&BoltDBFile, "boltdb-file", BoltDBFile, "Filename of the database for the BoltDB Handler")
	loadLDIFCmd := &cobra.Command{
		Use:   "load",
		Short: "Initialize a database from an LDIF file",
		Long: `The load command imports LDAP entries from an LDIF file and stores them into a BoltDB database.
If the database already exists it will be overwritten. The Entries in the LDIF file
need to	be correctly sorted, so that parent entries are created before their children.`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := loadLDIF(cmd, args); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}
	loadLDIFCmd.Flags().StringVar(&InputFile, "input-file", InputFile, "Filename of LDIF to read into database")
	loadLDIFCmd.Flags().StringVar(&LDAPBaseDN, "ldap-base-dn", LDAPBaseDN, "BaseDN for LDAP requests")
	if err := loadLDIFCmd.MarkFlagRequired("input-file"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if err := loadLDIFCmd.MarkFlagRequired("ldap-base-dn"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	boltdbCmd.AddCommand(loadLDIFCmd)

	return boltdbCmd
}

func loadLDIF(_ *cobra.Command, _ []string) error {
	loader, err := load.NewLDIFLoader(LogLevel, BoltDBFile, LDAPBaseDN)
	if err != nil {
		return err
	}
	return loader.Load(InputFile)
}
