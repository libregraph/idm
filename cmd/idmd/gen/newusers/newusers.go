/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 The LibreGraph Authors.
 */

package newusers

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/alexedwards/argon2id"
	"github.com/spf13/cobra"

	"github.com/libregraph/idm"
	"github.com/libregraph/idm/pkg/ldappassword"
)

var (
	DefaultFormat         = "ldif"
	DefaultPasswordScheme = "{ARGON2}"

	DefaultArgon2Params *argon2id.Params

	DefaultMinPasswordStrength = 3

	DefaultLDIFBaseDN     = "ou=Users,ou={{.Company}},{{.BaseDN}}"
	DefaultLDIFMailDomain = ""
)

var DefaultLDIFUserTemplate = `<<- /* */ ->>
dn: uid=<<.entry.Name>>,<<.BaseDN>>
objectClass: posixAccount
objectClass: top
objectClass: inetOrgPerson
uid: <<.entry.Name>>
uidNumber: <<with .detail.uidNumber>><<.>><<else>><<AutoIncrement>><<end>>
<<- with .detail.gidNumber>>
gidNumber: <<.>>
<<- end>>
<<- with .detail.userPassword>>
userPassword: <<.>>
<<- end>>
mail: <<.entry.Name>>@{{.MailDomain}}
<<- range .detail.mail>>
mailAlternateAddress: <<.>>
<<- end>>
cn: <<.detail.cn>>
<<- with .detail.givenName>>
givenName: <<.>>
<<- end>>
<<- with .detail.sn>>
sn: <<.>>
<<- end>>
`

func setDefaults() {
	if DefaultArgon2Params == nil {
		DefaultArgon2Params = ldappassword.Argon2DefaultParams
	}

	if DefaultLDIFMailDomain == "" {
		DefaultLDIFMailDomain = idm.DefaultMailDomain
	}
}

func CommandNewusers() *cobra.Command {
	setDefaults()

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
	newusersCmd.Flags().StringVar(&DefaultPasswordScheme, "password-scheme", DefaultPasswordScheme, "Password hash algorithm, supports: {ARGON2}, {CLEARTEXT}")
	newusersCmd.Flags().Uint32Var(&DefaultArgon2Params.Memory, "argon2-memory", DefaultArgon2Params.Memory, "Amount of memory used for ARGON2 password hashing in Kibibytes")
	newusersCmd.Flags().Uint32Var(&DefaultArgon2Params.Iterations, "argon2-iterations", DefaultArgon2Params.Iterations, "Number of iterations over memory used for ARGON2 password hashing")
	newusersCmd.Flags().Uint8Var(&DefaultArgon2Params.Parallelism, "argon2-lanes", DefaultArgon2Params.Parallelism, "Number of lanes used for ARGON2 password hashing")
	newusersCmd.Flags().IntVar(&DefaultMinPasswordStrength, "min-password-strength", DefaultMinPasswordStrength, "Mimimal required password strength (0=too guessable, 1=very guessable, 2=somewhat guessable, 4=safely unguessable, 5=very unguessable)")

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
		r = f
	} else {
		r = os.Stdin
	}

	ldappassword.Argon2DefaultParams.Memory = DefaultArgon2Params.Memory
	ldappassword.Argon2DefaultParams.Iterations = DefaultArgon2Params.Iterations
	ldappassword.Argon2DefaultParams.Parallelism = DefaultArgon2Params.Parallelism

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
		e := &entry{
			line: count,
			raw:  line,

			Name:   parts[0],
			Passwd: parts[1],
			UID:    parts[2],
			GID:    parts[3],
			Gecos:  parts[4],
			Dir:    parts[5],
			Shell:  parts[6],
		}
		if e.Passwd != "" {
			score := ldappassword.EstimatePasswordStrength(e.Passwd, nil)
			if score < DefaultMinPasswordStrength {
				return nil, fmt.Errorf("secret not secure in line %d (score %d)", e.line, score)
			}
		}

		results = append(results, e)

	}

	return results, nil
}
