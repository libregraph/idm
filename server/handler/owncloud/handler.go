/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package owncloud

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pkg/errors"

	"github.com/go-ldap/ldap/v3"
	"github.com/sirupsen/logrus"

	"github.com/libregraph/idm/pkg/ldapserver"
	"github.com/libregraph/idm/pkg/owncloudpassword"
	"github.com/libregraph/idm/server/handler"

	// Provides mysql drivers
	_ "github.com/go-sql-driver/mysql"
)

type ocHandler struct {
	options *Options

	logger logrus.FieldLogger

	db *sql.DB

	hasher owncloudpassword.Hasher

	baseDN                  string
	allowLocalAnonymousBind bool

	ctx context.Context
}

var _ handler.Handler = (*ocHandler)(nil) // Verify that *ldifHandler implements handler.Handler.

func NewOwnCloudHandler(logger logrus.FieldLogger, options *Options) (handler.Handler, error) {
	if options.BaseDN == "" {
		return nil, fmt.Errorf("base dn is empty")
	}

	h := &ocHandler{
		options: options,
		logger:  logger,

		hasher: owncloudpassword.NewHasher(&owncloudpassword.Options{}), // TODO make legacy hash configurable

		baseDN:                  strings.ToLower(options.BaseDN),
		allowLocalAnonymousBind: options.AllowLocalAnonymousBind,
		//joinUsername: options.joinUsername,
		//joinUUID: options.joinUUID,

		ctx: context.Background(),
	}

	err := h.open()
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h *ocHandler) open() error {
	if !strings.EqualFold(h.options.BaseDN, h.baseDN) {
		return fmt.Errorf("mismatched BaseDN")
	}

	var err error
	h.db, err = sql.Open("mysql", h.options.DSN)
	if err != nil {
		return errors.Wrap(err, "error connecting to the database")
	}
	h.db.SetConnMaxLifetime(time.Minute * 3)
	h.db.SetMaxOpenConns(10)
	h.db.SetMaxIdleConns(10)

	err = h.db.Ping()
	if err != nil {
		return errors.Wrap(err, "error connecting to the database")
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
	bindDN = strings.ToLower(bindDN)

	logger := h.logger.WithFields(logrus.Fields{
		"bind_dn":     bindDN,
		"remote_addr": conn.RemoteAddr().String(),
	})

	if err := h.validateBindDN(bindDN, conn); err != nil {
		logger.WithError(err).Debugln("ldap bind request BindDN validation failed")
		return ldap.LDAPResultInsufficientAccessRights, nil
	}

	if bindSimplePw == "" {
		logger.Debugf("ldap anonymous bind request")
		if bindDN == "" {
			return ldap.LDAPResultSuccess, nil
		} else {
			return ldap.LDAPResultUnwillingToPerform, nil
		}
	} else {
		logger.Debugf("ldap bind request")
	}

	baseDN := strings.ToLower("," + h.options.BaseDN)
	parts := strings.Split(strings.TrimSuffix(bindDN, baseDN), ",")
	if len(parts) > 2 {
		logger.WithField("numparts", len(parts)).Debugf("BindDN should have only one or two parts")
		return ldap.LDAPResultInvalidCredentials, nil
	}
	username := strings.TrimPrefix(parts[0], "cn=")

	// select user from OCDatabaseDSN

	q := `
		SELECT password
		FROM oc_accounts a
		LEFT JOIN oc_users u
			ON a.user_id=u.uid
		WHERE a.lower_user_id=?
		`

	row := h.db.QueryRowContext(h.ctx, q, username)
	var hash string
	if err := row.Scan(&hash); err != nil {
		logger.WithError(err).Debugf("ldap bind error")
		return ldap.LDAPResultInvalidCredentials, nil
	}

	if !h.hasher.Verify(bindSimplePw, hash) {
		logger.Debugf("ldap bind credentials error")
		return ldap.LDAPResultInvalidCredentials, nil
	}
	return ldap.LDAPResultSuccess, nil
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

func (h *ocHandler) validateBindDN(bindDN string, conn net.Conn) error {
	if bindDN == "" {
		if h.allowLocalAnonymousBind {
			host, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
			if net.ParseIP(host).IsLoopback() {
				return nil
			}
			return fmt.Errorf("anonymous BindDN rejected")
		}
		return fmt.Errorf("anonymous BindDN not allowed")
	}

	if strings.HasSuffix(bindDN, h.baseDN) {
		return nil
	}
	return fmt.Errorf("the BindDN is not in our BaseDN: %s", h.baseDN)
}
