/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package newusers

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	DefaultFormat       = "ldif"
	DefaultPasswordHash = "ARGON2"
)

func CommandNewusers() *cobra.Command {
	newusersCmd := &cobra.Command{
		Use:   "newusers [...args]",
		Short: "Create LDIF file for new users in batch",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := newusers(cmd, args); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	newusersCmd.Flags().StringVar(&DefaultFormat, "format", DefaultFormat, "Output format")

	return newusersCmd
}

func newusers(cmd *cobra.Command, args []string) error {
	var r io.Reader
	if len(args) > 0 && args[0] != "-" {
		fn, err := filepath.Abs(args[0])
		if err != nil {
			return fmt.Errorf("invalid path: %w", err)
		}

		f, err := os.Open(fn)
		if err != nil {
			return fmt.Errorf("failed to open: %w", err)
		}
		defer f.Close()
	} else {
		r = os.Stdin
	}

	if DefaultFormat == "ldif" {
		return outputLDIF(r)
	} else {
		return fmt.Errorf("unsupported output format: %v", DefaultFormat)
	}
}

type entry struct {
	line uint64
	raw  string

	Name   string
	Passwd string
	UID    string
	GID    string
	Gecos  string
	Dir    string
	Shell  string
}

func parsePasswdFile(r io.Reader) ([]*entry, error) {
	scanner := bufio.NewScanner(r)

	var results []*entry
	var count uint64
	for scanner.Scan() {
		count++
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if line[0] == '#' {
			// Skip comments.
			continue
		}

		// pw_name:pw_passwd:pw_uid:pw_gid:pw_gecos:pw_dir:pw_shell
		parts := strings.Split(line, ":")
		if len(parts) < 5 {
			return nil, fmt.Errorf("not enough fields in line %d", count)
		}
		results = append(results, &entry{
			line: count,
			raw:  line,

			Name:   parts[0],
			Passwd: parts[1],
			UID:    parts[2],
			GID:    parts[3],
			Gecos:  parts[4],
			Dir:    parts[5],
			Shell:  parts[6],
		})
	}

	return results, nil
}
