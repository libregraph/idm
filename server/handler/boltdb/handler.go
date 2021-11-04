/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package boltdb

import (
	"context"
	"fmt"
	"net"
	"path/filepath"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/sirupsen/logrus"

	"github.com/libregraph/idm/pkg/ldapserver"
	"github.com/libregraph/idm/pkg/ldbbolt"
	"github.com/libregraph/idm/server/handler"
)

type boltdbHandler struct {
	logger                  logrus.FieldLogger
	dbfile                  string
	baseDN                  string
	allowLocalAnonymousBind bool
	ctx                     context.Context
	bdb                     *ldbbolt.LdbBolt
}

type Options struct {
	BaseDN                  string
	AllowLocalAnonymousBind bool
}

func NewBoltDBHandler(logger logrus.FieldLogger, fn string, options *Options) (handler.Handler, error) {
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
	logger = logger.WithField("db", fn)

	h := &boltdbHandler{
		logger: logger,
		dbfile: fn,

		baseDN:                  strings.ToLower(options.BaseDN),
		allowLocalAnonymousBind: options.AllowLocalAnonymousBind,
		ctx:                     context.Background(),
	}

	err = h.setup()
	if err != nil {
		return nil, err
	}
	return h, nil
}

func (h *boltdbHandler) setup() error {
	bdb := &ldbbolt.LdbBolt{}

	if err := bdb.Configure(h.logger, h.baseDN, h.dbfile); err != nil {
		return err
	}

	if err := bdb.Initialize(); err != nil {
		return err
	}
	h.bdb = bdb
	return nil
}

func (h *boltdbHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldapserver.LDAPResultCode, error) {
	return ldap.LDAPResultSuccess, nil
}

func (h *boltdbHandler) Search(boundDN string, req *ldap.SearchRequest, conn net.Conn) (ldapserver.ServerSearchResult, error) {
	h.logger.WithField("op", "search").Debug("start")

	entries, _ := h.bdb.Search(req.BaseDN, req.Scope)

	return ldapserver.ServerSearchResult{
		Entries:    entries,
		Referrals:  []string{},
		Controls:   []ldap.Control{},
		ResultCode: ldap.LDAPResultSuccess,
	}, nil
}

func (h *boltdbHandler) Close(boundDN string, conn net.Conn) error {
	return nil
}

func (h *boltdbHandler) WithContext(ctx context.Context) handler.Handler {
	if ctx == nil {
		panic("nil context")
	}

	h2 := new(boltdbHandler)
	*h2 = *h
	h2.ctx = ctx
	return h2
}

func (h *boltdbHandler) Reload(ctx context.Context) error {
	return nil
}
