/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package handler

import (
	"crypto/subtle"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/amoghe/go-crypt"
	goldap "github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	nmcldap "github.com/nmcclain/ldap"
	"github.com/sirupsen/logrus"
	"github.com/spacewander/go-suffix-tree"
)

type ldifHandler struct {
	logger logrus.FieldLogger
	baseDN string

	l *ldif.LDIF
	t *suffix.Tree
}

func NewLDIFHandler(logger logrus.FieldLogger, fn string, baseDN string) (Handler, error) {
	if fn == "" {
		return nil, fmt.Errorf("file name is empty")
	}
	if baseDN == "" {
		return nil, fmt.Errorf("base dn is empty")
	}

	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}

	l := &ldif.LDIF{}
	err = ldif.Unmarshal(f, l)
	if err != nil {
		return nil, err
	}

	t := suffix.NewTree()

	// NOTE(longsleep): Meh nmcldap vs goldap - for now create the type which we need to return for search.
	var entry *goldap.Entry
	for _, entry = range l.AllEntries() {
		e := &nmcldap.Entry{
			DN:         strings.ToLower(entry.DN),
			Attributes: make([]*nmcldap.EntryAttribute, len(entry.Attributes)),
		}
		for i, a := range entry.Attributes {
			e.Attributes[i] = &nmcldap.EntryAttribute{
				Name:   a.Name,
				Values: a.Values,
			}
		}
		v, ok := t.Insert([]byte(e.DN), e)
		if !ok || v != nil {
			return nil, fmt.Errorf("duplicate value: %s", e.DN)
		}

		logger.Debugln("xxx dn", e.DN, e.GetAttributeValue("userPassword"))
	}
	logger.WithFields(logrus.Fields{
		"version":       l.Version,
		"entries_count": len(l.Entries),
		"tree_length":   t.Len(),
		"base_dn":       baseDN,
	}).Debugln("loaded LDIF from file")

	return &ldifHandler{
		logger: logger,
		baseDN: strings.ToLower(baseDN),

		l: l,
		t: t,
	}, nil
}

func (h *ldifHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode nmcldap.LDAPResultCode, err error) {
	bindDN = strings.ToLower(bindDN)

	logger := h.logger.WithFields(logrus.Fields{
		"bind_dn":     bindDN,
		"remote_addr": conn.RemoteAddr().String(),
	})

	logger.Debugf("ldap bind request")

	if !strings.HasSuffix(bindDN, h.baseDN) {
		err := fmt.Errorf("the BindDN is not in our BaseDN %s", h.baseDN)
		logger.WithError(err).Debugf("ldap bind error")
		return nmcldap.LDAPResultInvalidCredentials, nil
	}

	entryRecord, found := h.t.Get([]byte(bindDN))
	if !found {
		err := fmt.Errorf("user not found")
		logger.WithError(err).Debugf("ldap bind error")
		return nmcldap.LDAPResultInvalidCredentials, nil
	}
	entry := entryRecord.(*nmcldap.Entry)

	userPw := entry.GetAttributeValue("userPassword")
	userPwScheme := ""
	if userPw[0] == '{' {
		schemeEnd := strings.Index(userPw[1:], "}")
		if schemeEnd >= 1 {
			userPwScheme = userPw[1 : schemeEnd+1]
			userPw = userPw[schemeEnd+2:]
		}
	}

	switch userPwScheme {
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
			logger.WithError(fmt.Errorf("crypt error: %w", err)).Debugf("ldap bind error")
			return nmcldap.LDAPResultInvalidCredentials, nil
		}
		bindSimplePw = encrypted

	default:
	}

	if subtle.ConstantTimeCompare([]byte(userPw), []byte(bindSimplePw)) != 1 {
		err := fmt.Errorf("invalid credentials")
		logger.WithError(err).Debugf("bind error")
		return nmcldap.LDAPResultInvalidCredentials, nil
	}

	return nmcldap.LDAPResultSuccess, nil
}

func (h *ldifHandler) Search(bindDN string, searchReq nmcldap.SearchRequest, conn net.Conn) (result nmcldap.ServerSearchResult, err error) {
	bindDN = strings.ToLower(bindDN)
	searchBaseDN := strings.ToLower(searchReq.BaseDN)
	logger := h.logger.WithFields(logrus.Fields{
		"bind_dn":        bindDN,
		"search_base_dn": searchBaseDN,
		"remote_addr":    conn.RemoteAddr().String(),
	})

	logger.Debugf("ldap search request for %s", searchReq.Filter)

	if bindDN == "" {
		err := fmt.Errorf("anonymous BindDN not allowed")
		logger.WithError(err).Debugln("ldap search error")
		return nmcldap.ServerSearchResult{
			ResultCode: nmcldap.LDAPResultInsufficientAccessRights,
		}, err
	}

	if !strings.HasSuffix(bindDN, h.baseDN) {
		err := fmt.Errorf("the BindDN is not in our BaseDN: %s", h.baseDN)
		logger.WithError(err).Debugln("ldap search error")
		return nmcldap.ServerSearchResult{
			ResultCode: nmcldap.LDAPResultInsufficientAccessRights,
		}, err
	}

	if !strings.HasSuffix(searchBaseDN, h.baseDN) {
		err := fmt.Errorf("search BaseDN is not in our BaseDN %s", h.baseDN)
		return nmcldap.ServerSearchResult{
			ResultCode: nmcldap.LDAPResultInsufficientAccessRights,
		}, err
	}

	entries := []*nmcldap.Entry{}
	h.t.WalkSuffix([]byte(searchBaseDN), func(key []byte, entryRecord interface{}) bool {
		// NOTE(longsleep): The nmcldap search handler mutates the entries it processes, so we make a copy.
		entry := entryRecord.(*nmcldap.Entry)
		e := &nmcldap.Entry{
			DN:         entry.DN,
			Attributes: make([]*nmcldap.EntryAttribute, len(entry.Attributes)),
		}
		copy(e.Attributes, entry.Attributes)
		entries = append(entries, e)
		return false
	})

	return nmcldap.ServerSearchResult{
		Entries:    entries,
		Referrals:  []string{},
		Controls:   []nmcldap.Control{},
		ResultCode: nmcldap.LDAPResultSuccess,
	}, nil
}

func (h *ldifHandler) Close(bindDN string, conn net.Conn) error {
	return nil
}
