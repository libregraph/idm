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

	h.logger.WithFields(logrus.Fields{
		//"version":       l.Version,
		"accounts_count": h.GetAccountCount(),
		"groups_count":   h.GetGroupCount(),
		"base_dn":        h.options.BaseDN,
		//"indexes":       len(index),
	}).Debugln("database opened")

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
		logger.Debug("ldap anonymous bind request")
		if bindDN == "" {
			return ldap.LDAPResultSuccess, nil
		} else {
			return ldap.LDAPResultUnwillingToPerform, nil
		}
	} else {
		logger.Debug("ldap bind request")
	}

	baseDN := strings.ToLower("," + h.options.BaseDN)
	parts := strings.Split(strings.TrimSuffix(bindDN, baseDN), ",")
	if len(parts) > 2 {
		logger.WithField("numparts", len(parts)).Debug("BindDN should have only one or two parts")
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
	bindDN = strings.ToLower(bindDN)
	searchBaseDN := strings.ToLower(searchReq.BaseDN)
	logger := h.logger.WithFields(logrus.Fields{
		"bind_dn":        bindDN,
		"search_base_dn": searchBaseDN,
		"remote_addr":    conn.RemoteAddr().String(),
		"controls":       searchReq.Controls,
		"size_limit":     searchReq.SizeLimit,
	})

	logger.Debugf("ldap search request for %s", searchReq.Filter)

	if err := h.validateBindDN(bindDN, conn); err != nil {
		logger.WithError(err).Debugln("ldap search request BindDN validation failed")
		return ldapserver.ServerSearchResult{
			ResultCode: ldap.LDAPResultInsufficientAccessRights,
		}, err
	}

	entries := []*ldap.Entry{}
	objectclasses, conditionsSQL, values, err := h.parseFilterToSQLFragments(searchReq.Filter)
	if err != nil {
		return ldapserver.ServerSearchResult{
			ResultCode: ldap.LDAPResultOperationsError,
		}, err
	}
	objectclass := ""
	for i := range objectclasses {
		if objectclass == "" {
			objectclass = objectclasses[i]
		} else if objectclasses[i] != objectclass {
			return ldapserver.ServerSearchResult{
				ResultCode: ldap.LDAPResultUnwillingToPerform,
			}, fmt.Errorf("search error: only one type of objectclass supported")
		}
	}

	selectSQL := "SELECT id, email, user_id, display_name, quota, last_login, backend, home, state"
	whereSQL := ""
	if conditionsSQL != "" {
		whereSQL = " WHERE " + conditionsSQL
	}

	switch objectclass {
	case "posixaccount", "person", "organizationalperson", "inetorgperson":
		fromSQL := " FROM oc_accounts"
		if h.options.JoinUsername {
			selectSQL += ", p.configvalue AS username"
			fromSQL += `LEFT JOIN oc_preferences p
							ON a.user_id=p.userid
							AND p.appid='core'
							AND p.configkey='username'`
		} else {
			// fallback to user_id as username
			selectSQL += ", user_id AS username"
		}
		if h.options.JoinUUID {
			selectSQL += ", p2.configvalue AS ownclouduuid"
			fromSQL += `LEFT JOIN oc_preferences p2
							ON a.user_id=p2.userid
							AND p2.appid='core'
							AND p2.configkey='ownclouduuid'`
		} else {
			// fallback to user_id as ownclouduuid
			selectSQL += ", user_id AS ownclouduuid"
		}
		query := selectSQL + fromSQL + whereSQL
		rows, err := h.db.Query(query, values...)
		if err != nil {
			return ldapserver.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, err
		}
		defer rows.Close()

		for rows.Next() {
			a, err := h.rowToAccount(h.ctx, rows)
			if err != nil {
				// log error and continue
				logger.WithError(err).Error("could not convert row to account")
				continue
			}
			entry, err := h.accountToEntry(h.ctx, a)
			if err != nil {
				// log error and continue
				logger.WithError(err).Error("could not convert account to entry")
				continue
			}

			// Filter attributes from entry.
			// we do not build a special select query, because it would also require different row.Scan calls
			resultCode, err := ldapserver.ServerFilterAttributes(searchReq.Attributes, entry)
			if err != nil {
				return ldapserver.ServerSearchResult{
					ResultCode: resultCode,
				}, err
			}

			entries = append(entries, entry)
		}
		return ldapserver.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess}, nil

	case "group":
		//fromSQL := " FROM oc_groups"
		return ldapserver.ServerSearchResult{
			ResultCode: ldap.LDAPResultUnwillingToPerform,
		}, fmt.Errorf("search error: only 'person' objectclass supported")
	default:
		return ldapserver.ServerSearchResult{
			ResultCode: ldap.LDAPResultUnwillingToPerform,
		}, fmt.Errorf("search error: only 'person' or 'group' objectclass supported")
	}

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
