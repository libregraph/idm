/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package passwd

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/sethvargo/go-password/password"
	"github.com/spf13/cobra"

	"stash.kopano.io/kgol/kidm/server/handler/ldif"
)

var (
	DefaultPasswordScheme = "{ARGON2}"

	DefaultArgon2Memory     = ldif.Argon2DefaultParams.Memory
	DefaultArgon2Iterations = ldif.Argon2DefaultParams.Iterations
	DefaultArgon2Lanes      = ldif.Argon2DefaultParams.Parallelism

	OmitTrailingNewline = false
)

func CommandPasswd() *cobra.Command {
	passwdCmd := &cobra.Command{
		Use:   "passwd",
		Short: "Password utility",
		Long:  "Generate userPassword value suitable for use in LDIF files.",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			if err := passwd(cmd, args); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	passwdCmd.Flags().StringVar(&DefaultPasswordScheme, "password-scheme", DefaultPasswordScheme, "Password hash algorithm, supports: {ARGON2}, {CLEARTEXT}")
	passwdCmd.Flags().Uint32Var(&DefaultArgon2Memory, "argon2-memory", DefaultArgon2Memory, "Amount of memory used for ARGON2 password hashing in Kibibytes")
	passwdCmd.Flags().Uint32Var(&DefaultArgon2Iterations, "argon2-iterations", DefaultArgon2Iterations, "Number of iterations over memory used for ARGON2 password hashing")
	passwdCmd.Flags().Uint8Var(&DefaultArgon2Lanes, "argon2-lanes", DefaultArgon2Lanes, "Number of lanes used for ARGON2 password hashing")

	passwdCmd.Flags().StringP("secret", "s", "", "The secret to hash")
	passwdCmd.Flags().BoolP("generate", "g", false, "Generate a random secret (forces cleartext scheme)")
	passwdCmd.Flags().StringP("secret-file", "T", "", "File containing the secret to be hashed")

	passwdCmd.Flags().BoolVarP(&OmitTrailingNewline, "omit-newline", "n", false, "Omit the trailing newline; useful to pipe the credentials into a command")

	return passwdCmd
}

func passwd(cmd *cobra.Command, args []string) error {
	ldif.Argon2DefaultParams.Memory = DefaultArgon2Memory
	ldif.Argon2DefaultParams.Iterations = DefaultArgon2Iterations
	ldif.Argon2DefaultParams.Parallelism = DefaultArgon2Lanes

	var secret string
	var exclusive = 0
	err := func() error {
		if cmd.Flags().Changed("secret") {
			if exclusive == 0 {
				secret, _ = cmd.Flags().GetString("secret")
			}
			exclusive++
		}
		if cmd.Flags().Changed("secret-file") {
			if exclusive == 0 {
				fn, _ := cmd.Flags().GetString("secret-file")
				fn = filepath.Clean(fn)
				secretBytes, readErr := ioutil.ReadFile(fn)
				if readErr != nil {
					return fmt.Errorf("failed to read secret file: %w", readErr)
				}
				secret = string(secretBytes)
			}
			exclusive++
		}
		if cmd.Flags().Changed("generate") {
			if exclusive == 0 {
				var genError error
				secret, genError = password.Generate(12, 2, 2, false, false)
				if genError != nil {
					return fmt.Errorf("password generator error: %w", genError)
				}
				DefaultPasswordScheme = "{CLEARTEXT}"
			}
			exclusive++
		}
		return nil
	}()
	if exclusive > 1 {
		return fmt.Errorf("-s -g and -T are mutually exclusive")
	} else if exclusive == 0 {
		secret, err = promptForPassword()
		if err != nil {
			return err
		}
	}
	if strings.TrimSpace(secret) == "" {
		return fmt.Errorf("secret is empty")
	}

	hash, err := ldif.HashPassword(secret, DefaultPasswordScheme)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stdout, hash)
	if !OmitTrailingNewline {
		fmt.Fprintf(os.Stdout, "\n")
	}
	return nil
}
