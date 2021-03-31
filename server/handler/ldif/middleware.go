/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ldif

import (
	"fmt"
	"net"
	"strings"

	"github.com/go-ldap/ldif"
	nmcldap "github.com/nmcclain/ldap"
	"github.com/sirupsen/logrus"
	"github.com/spacewander/go-suffix-tree"

	"stash.kopano.io/kgol/kidm/server/handler"
)

type ldifMiddleware struct {
	logger logrus.FieldLogger

	baseDN string

	l *ldif.LDIF
	t *suffix.Tree

	next handler.Handler
}

func NewLDIFMiddleware(logger logrus.FieldLogger, fn string, baseDN string) (handler.Middleware, error) {
	if fn == "" {
		return nil, fmt.Errorf("file name is empty")
	}
	if baseDN == "" {
		return nil, fmt.Errorf("base dn is empty")
	}

	l, err := parseLDIFFile(fn)
	if err != nil {
		return nil, err
	}

	t, err := treeFromLDIF(l, nil)
	if err != nil {
		return nil, err
	}
	logger.WithFields(logrus.Fields{
		"version":       l.Version,
		"entries_count": len(l.Entries),
		"tree_length":   t.Len(),
		"base_dn":       baseDN,
	}).Debugln("loaded config LDIF from file")

	return &ldifMiddleware{
		logger: logger,
		baseDN: strings.ToLower(baseDN),

		l: l,
		t: t,
	}, nil
}

var _ handler.Handler = (*ldifMiddleware)(nil) // Verify that *configHandler implements handler.Handler.

func (h *ldifMiddleware) WithHandler(next handler.Handler) handler.Handler {
	h.next = next

	return h
}

func (h *ldifMiddleware) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode nmcldap.LDAPResultCode, err error) {
	entryRecord, found := h.t.Get([]byte(bindDN))
	if found {
		logger := h.logger.WithFields(logrus.Fields{
			"bind_dn":     bindDN,
			"remote_addr": conn.RemoteAddr().String(),
		})

		if !strings.HasSuffix(bindDN, h.baseDN) {
			err := fmt.Errorf("the BindDN is not in our BaseDN %s", h.baseDN)
			logger.WithError(err).Infoln("ldap bind error")
			return nmcldap.LDAPResultInvalidCredentials, nil
		}

		if err := entryRecord.(*ldifEntry).validatePassword(bindSimplePw); err != nil {
			logger.WithError(err).Infoln("bind error")
			return nmcldap.LDAPResultInvalidCredentials, nil
		}
	}

	return h.next.Bind(bindDN, bindSimplePw, conn)
}

func (h *ldifMiddleware) Search(bindDN string, searchReq nmcldap.SearchRequest, conn net.Conn) (result nmcldap.ServerSearchResult, err error) {
	return h.next.Search(bindDN, searchReq, conn)
}

func (h *ldifMiddleware) Close(bindDN string, conn net.Conn) error {
	return h.next.Close(bindDN, conn)
}
