/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package ldappassword

import (
	"crypto/sha1" //nolint,gosec
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/GehirnInc/crypt"
	_ "github.com/GehirnInc/crypt/apr1_crypt"
	_ "github.com/GehirnInc/crypt/md5_crypt"
	_ "github.com/GehirnInc/crypt/sha256_crypt"
	_ "github.com/GehirnInc/crypt/sha512_crypt"
	"github.com/alexedwards/argon2id"
	"github.com/trustelem/zxcvbn"
)

var Argon2DefaultParams = argon2id.DefaultParams

func Validate(password string, hash string) (bool, error) {
	algorithm := ""
	if hash[0] == '{' {
		algorithmEnd := strings.Index(hash[0:], "}")
		if algorithmEnd >= 1 {
			algorithm = hash[0 : algorithmEnd+1]
			hash = hash[algorithmEnd+1:]
		}
	}

	hashBytes := []byte(hash)
	var passwordBytes []byte

	switch strings.ToUpper(algorithm) {
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
		if !crypt.IsHashSupported(hash) {
			return false, errors.New("unsupported crypt format")
		}
		crypter := crypt.NewFromHash(hash)
		err := crypter.Verify(hash, []byte(password))
		if err != nil {
			if errors.Is(err, crypt.ErrKeyMismatch) {
				return false, fmt.Errorf("invalid credentials")
			}
			return false, fmt.Errorf("crypt error: %w", err)
		}
		return true, nil

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

func Hash(password string, algorithm string) (string, error) {
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

func EstimatePasswordStrength(password string, userInputs []string) int {
	result := zxcvbn.PasswordStrength(password, userInputs)
	return result.Score
}
