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
)

var Argon2DefaultParams = argon2id.DefaultParams

func ValidatePassword(password string, hash string) (bool, error) {
	algorithm := ""
	if hash[0] == '{' {
		algorithmEnd := strings.Index(hash[0:], "}")
		if algorithmEnd >= 1 {
			algorithm = hash[0 : algorithmEnd+1]
			hash = hash[algorithmEnd+2:]
		}
	}

	hashBytes := []byte(hash)
	var passwordBytes []byte

	switch algorithm {
	case "":
		// No password scheme, direct comparison.
		passwordBytes = []byte(password)

	case "{ARGON2}":
		// Follows the format used by the Argon2 reference C implementation and looks like this:
		// $argon2id$v=19$m=65536,t=3,p=2$c29tZXNhbHQ$RdescudvJCsgt3ub+b+dWRWJTmaaJObG
		match, err := argon2id.ComparePasswordAndHash(password, hash)
		if err != nil {
			return false, fmt.Errorf("argon2 error: %w", err)
		}
		if !match {
			return false, fmt.Errorf("invalid credentials")
		}
		return true, nil

	case "{CRYPT}":
		// By default the salt is a two character string.
		salt := hash[:2]
		if hash[0] == '$' {
			// In the glibc2 version, salt format for additional encryption
			// $id$salt$encrypted.
			hashParts := strings.SplitN(hash, "$", 5)
			if len(hashParts) == 5 {
				salt = strings.Join(hashParts[:4], "$")
			}
		}
		encrypted, err := crypt.Crypt(password, salt)
		if err != nil {
			return false, fmt.Errorf("crypt error: %w", err)
		}
		passwordBytes = []byte(encrypted)

	case "{SSHA}":
		// BASE64(SHA-1(clear_text + salt) + salt)
		// The salt is 4 bytes long.
		decodedBytes, err := base64.StdEncoding.DecodeString(hash)
		if err != nil {
			return false, fmt.Errorf("ssha error: %w", err)
		}
		salt := decodedBytes[len(decodedBytes)-4:]
		h := sha1.New() //nolint,gosec
		h.Write([]byte(password))
		h.Write(salt)
		passwordBytes = h.Sum(nil)
		passwordBytes = append(passwordBytes, salt...)
		hashBytes = decodedBytes

	default:
		return false, fmt.Errorf("unsupported password algorithm: %s", algorithm)
	}

	if subtle.ConstantTimeCompare(hashBytes, passwordBytes) != 1 {
		return false, fmt.Errorf("invalid credentials")
	}
	return true, nil
}

func HashPassword(password string, algorithm string) (string, error) {
	var result string

	switch algorithm {
	case "", "{CLEARTEXT}":
		result = password

	case "{ARGON2}":
		hash, hashErr := argon2id.CreateHash(password, Argon2DefaultParams)
		if hashErr != nil {
			return "", fmt.Errorf("password hash error: %w", hashErr)
		}
		result = "{ARGON2}" + hash

	default:
		return "", fmt.Errorf("password hash alg not supported: %s", algorithm)
	}

	return result, nil
}
