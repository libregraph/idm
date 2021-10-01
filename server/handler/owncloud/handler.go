/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package owncloud

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/sirupsen/logrus"

	"github.com/libregraph/idm/pkg/ldapserver"
	"github.com/libregraph/idm/server/handler"
)

type ocHandler struct {
	logger  logrus.FieldLogger
	fn      string
	options *Options

	baseDN                  string
	allowLocalAnonymousBind bool

	ctx context.Context
}

var _ handler.Handler = (*ocHandler)(nil) // Verify that *ldifHandler implements handler.Handler.

func NewLDIFHandler(logger logrus.FieldLogger, fn string, options *Options) (handler.Handler, error) {
	if fn == "" {
		return nil, fmt.Errorf("file name is empty")
	}
	if options.BaseDN == "" {
		return nil, fmt.Errorf("base dn is empty")
	}

	fn, err := filepath.Abs(fn)
	if err != nil {
		return nil, err
	}
	logger = logger.WithField("fn", fn)

	h := &ocHandler{
		logger:  logger,
		fn:      fn,
		options: options,

		baseDN:                  strings.ToLower(options.BaseDN),
		allowLocalAnonymousBind: options.AllowLocalAnonymousBind,

		ctx: context.Background(),
	}

	err = h.open()
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h *ocHandler) open() error {
	if !strings.EqualFold(h.options.BaseDN, h.baseDN) {
		return fmt.Errorf("mismatched BaseDN")
	}

	//open db
	h.logger.WithFields(logrus.Fields{
		//"version":       l.Version,
		//"entries_count": len(l.Entries),
		//"tree_length":   t.Len(),
		"base_dn": h.options.BaseDN,
		//"indexes":       len(index),
	}).Debugln("loaded LDIF")

	return nil
}

func (h *ocHandler) WithContext(ctx context.Context) handler.Handler {
	if ctx == nil {
		panic("nil context")
	}

	h2 := new(ocHandler)
	*h2 = *h
	h2.ctx = ctx
	return h2
}

func (h *ocHandler) Reload(ctx context.Context) error {
	return h.open()
}

func (h *ocHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldapserver.LDAPResultCode, error) {
	return ldap.LDAPResultNotSupported, nil
}

func (h *ocHandler) Search(bindDN string, searchReq *ldap.SearchRequest, conn net.Conn) (ldapserver.ServerSearchResult, error) {
	return ldapserver.ServerSearchResult{
		ResultCode: ldap.LDAPResultNotSupported,
	}, nil
}

func (h *ocHandler) Close(bindDN string, conn net.Conn) error {
	h.logger.WithFields(logrus.Fields{
		"bind_dn":     bindDN,
		"remote_addr": conn.RemoteAddr().String(),
	}).Debugln("ldap close")

	return nil
}
