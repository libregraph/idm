/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ldif

import (
	"crypto/sha1" //nolint,gosec
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/alexedwards/argon2id"
	"github.com/amoghe/go-crypt"
	"github.com/go-ldap/ldap/v3"
)

type ldifEntry struct {
	*ldap.Entry

	UserPassword *ldap.EntryAttribute
}

func (entry *ldifEntry) validatePassword(bindSimplePw string) error {
	userPw := entry.UserPassword.Values[0]
	userPwScheme := ""
	if userPw[0] == '{' {
		schemeEnd := strings.Index(userPw[1:], "}")
		if schemeEnd >= 1 {
			userPwScheme = userPw[1 : schemeEnd+1]
			userPw = userPw[schemeEnd+2:]
		}
	}

	userPwBytes := []byte(userPw)
	var bindSimplePwBytes []byte

	switch userPwScheme {
	case "":
		// No password scheme, direct comparison.
		bindSimplePwBytes = []byte(bindSimplePw)

	case "ARGON2":
		// Follows the format used by the Argon2 reference C implementation and looks like this:
		// $argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
		match, err := argon2id.ComparePasswordAndHash(bindSimplePw, userPw)
		if err != nil {
			return fmt.Errorf("argon2 error: %w", err)
		}
		if !match {
			return fmt.Errorf("invalid credentials")
		}
		return nil

	case "CRYPT":
		// By default the salt is a two character string.
		salt := userPw[:2]
		if userPw[0] == '$' {
			// In the glibc2 version, salt format for additional encryption
			// $id$salt$encrypted.
			userPwParts := strings.SplitN(userPw, "$", 5)
			if len(userPwParts) == 5 {
				salt = strings.Join(userPwParts[:4], "$")
			}
		}
		encrypted, err := crypt.Crypt(bindSimplePw, salt)
		if err != nil {
			return fmt.Errorf("crypt error: %w", err)
		}
		bindSimplePwBytes = []byte(encrypted)

	case "SSHA":
		// BASE64(SHA-1(clear_text + salt) + salt)
		// The salt is 4 bytes long.
		decodedBytes, err := base64.StdEncoding.DecodeString(userPw)
		if err != nil {
			return fmt.Errorf("ssha error: %w", err)
		}
		salt := decodedBytes[len(decodedBytes)-4:]
		h := sha1.New() //nolint,gosec
		h.Write([]byte(bindSimplePw))
		h.Write(salt)
		bindSimplePwBytes = h.Sum(nil)
		bindSimplePwBytes = append(bindSimplePwBytes, salt...)
		userPwBytes = decodedBytes

	default:
		return fmt.Errorf("unsupported password scheme: %s, %s", userPwScheme, userPw)
	}

	if subtle.ConstantTimeCompare(userPwBytes, bindSimplePwBytes) != 1 {
		return fmt.Errorf("invalid credentials")
	}
	return nil
}
