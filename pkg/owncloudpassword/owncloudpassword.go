/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package owncloudpassword

import (
	"crypto/hmac"
	"crypto/sha1" //nolint,gosec
	"encoding/hex"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type Hasher interface {
	Verify(password, hash string) bool
}

func NewHasher(options *Options) Hasher {
	return &hasher{
		legacySalt: options.LegacySalt,
	}
}

type hasher struct {
	legacySalt string
}

func (h *hasher) Verify(password, hash string) bool {
	splitHash := strings.SplitN(hash, "|", 2)
	switch len(splitHash) {
	case 2:
		if splitHash[0] == "1" {
			return h.verifyHashV1(password, splitHash[1])
		}
	case 1:
		return h.legacyHashVerify(password, hash)
	}
	return false
}

func (h *hasher) legacyHashVerify(password, hash string) bool {
	// TODO rehash $newHash = $this->hash($message);
	switch len(hash) {
	case 60: // legacy PHPass hash
		return nil == bcrypt.CompareHashAndPassword([]byte(hash), []byte(password+h.legacySalt))
	case 40: // legacy sha1 hash
		h := sha1.Sum([]byte(password))
		return hmac.Equal([]byte(hash), []byte(hex.EncodeToString(h[:])))
	}
	return false
}
func (h *hasher) verifyHashV1(password, hash string) bool {
	// TODO implement password_needs_rehash
	return nil == bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
