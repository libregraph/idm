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

	"stash.kopano.io/kgol/kidm/server/handler/ldif"
)

var (
	DefaultFormat       = "ldif"
	DefaultPasswordHash = "ARGON2"

	DefaultArgon2Memory     = ldif.Argon2DefaultParams.Memory
	DefaultArgon2Iterations = ldif.Argon2DefaultParams.Iterations
	DefaultArgon2Lanes      = ldif.Argon2DefaultParams.Parallelism
)

func CommandNewusers() *cobra.Command {
	newusersCmd := &cobra.Command{
		Use:   "newusers [<file>|-]",
		Short: "Create LDIF file for new users in batch",
		Long:  "Create LDIF file for new users in batch from text input. Input is read either from <file> or from stdin if '-' is used as argument.",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := newusers(cmd, args); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	newusersCmd.Flags().StringVar(&DefaultFormat, "format", DefaultFormat, "Output format")
	newusersCmd.Flags().StringVar(&DefaultPasswordHash, "password-hash", DefaultPasswordHash, "Password hash algorithm, supports: ARGON2")
	newusersCmd.Flags().Uint32Var(&DefaultArgon2Memory, "argon2-memory", DefaultArgon2Memory, "Amount of memory used for ARGON2 password hashing in Kibibytes")
	newusersCmd.Flags().Uint32Var(&DefaultArgon2Iterations, "argon2-iterations", DefaultArgon2Iterations, "Number of iterations over memory used for ARGON2 password hashing")
	newusersCmd.Flags().Uint8Var(&DefaultArgon2Lanes, "argon2-lanes", DefaultArgon2Lanes, "Number of lanes used for ARGON2 password hashing")

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

	ldif.Argon2DefaultParams.Memory = DefaultArgon2Memory
	ldif.Argon2DefaultParams.Iterations = DefaultArgon2Iterations
	ldif.Argon2DefaultParams.Parallelism = DefaultArgon2Lanes

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
