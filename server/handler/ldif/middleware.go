/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ldif

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/sirupsen/logrus"
	"github.com/spacewander/go-suffix-tree"

	"stash.kopano.io/kgol/kidm/internal/ldapserver"
	"stash.kopano.io/kgol/kidm/server/handler"
)

type ldifMiddleware struct {
	logger logrus.FieldLogger

	baseDN string

	l *ldif.LDIF
	t *suffix.Tree

	next handler.Handler
}

func NewLDIFMiddleware(logger logrus.FieldLogger, fn string, options *Options) (handler.Middleware, error) {
	if fn == "" {
		return nil, fmt.Errorf("file name is empty")
	}
	if options.BaseDN == "" {
		return nil, fmt.Errorf("base dn is empty")
	}

	logger.WithFields(logrus.Fields{
		"fn": fn,
	}).Debugln("loading LDIF from file")
	l, err := parseLDIFFile(fn, options)
	if err != nil {
		return nil, err
	}

	t, err := treeFromLDIF(l, nil, options)
	if err != nil {
		return nil, err
	}
	logger.WithFields(logrus.Fields{
		"version":       l.Version,
		"entries_count": len(l.Entries),
		"tree_length":   t.Len(),
		"base_dn":       options.BaseDN,
		"fn":            fn,
	}).Debugln("loaded LDIF from file")

	return &ldifMiddleware{
		logger: logger,
		baseDN: strings.ToLower(options.BaseDN),

		l: l,
		t: t,
	}, nil
}

var _ handler.Handler = (*ldifMiddleware)(nil) // Verify that *configHandler implements handler.Handler.

func (h *ldifMiddleware) WithHandler(next handler.Handler) handler.Handler {
	h.next = next

	return h
}

func (h *ldifMiddleware) WithContext(ctx context.Context) handler.Handler {
	if ctx == nil {
		panic("nil context")
	}

	h2 := new(ldifMiddleware)
	*h2 = *h
	h2.next = h.next.WithContext(ctx)
	return h2
}

func (h *ldifMiddleware) Bind(bindDN, bindSimplePw string, conn net.Conn) (resultCode ldapserver.LDAPResultCode, err error) {
	bindDN = strings.ToLower(bindDN)

	if bindDN == "" {
		return h.next.Bind(bindDN, bindSimplePw, conn)
	}

	entryRecord, found := h.t.Get([]byte(bindDN))
	if found {
		logger := h.logger.WithFields(logrus.Fields{
			"bind_dn":     bindDN,
			"remote_addr": conn.RemoteAddr().String(),
		})

		if !strings.HasSuffix(bindDN, h.baseDN) {
			err := fmt.Errorf("the BindDN is not in our BaseDN %s", h.baseDN)
			logger.WithError(err).Infoln("ldap bind error")
			return ldap.LDAPResultInvalidCredentials, nil
		}

		if err := entryRecord.(*ldifEntry).validatePassword(bindSimplePw); err != nil {
			logger.WithError(err).Infoln("bind error")
			return ldap.LDAPResultInvalidCredentials, nil
		}

		return ldap.LDAPResultSuccess, nil
	}

	return h.next.Bind(bindDN, bindSimplePw, conn)
}

func (h *ldifMiddleware) Search(bindDN string, searchReq *ldap.SearchRequest, conn net.Conn) (result ldapserver.ServerSearchResult, err error) {
	return h.next.Search(bindDN, searchReq, conn)
}

func (h *ldifMiddleware) Close(bindDN string, conn net.Conn) error {
	return h.next.Close(bindDN, conn)
}
