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

	db        *sql.DB
	selectSQL string

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

	sel := "SELECT id, email, user_id, display_name, quota, last_login, backend, home, state"
	from := `
		FROM oc_accounts a
		`
	if options.JoinUsername {
		sel += ", p.configvalue AS username"
		from += `LEFT JOIN oc_preferences p
						ON a.user_id=p.userid
						AND p.appid='core'
						AND p.configkey='username'`
	} else {
		// fallback to user_id as username
		sel += ", user_id AS username"
	}
	if options.JoinUUID {
		sel += ", p2.configvalue AS ownclouduuid"
		from += `LEFT JOIN oc_preferences p2
						ON a.user_id=p2.userid
						AND p2.appid='core'
						AND p2.configkey='ownclouduuid'`
	} else {
		// fallback to user_id as ownclouduuid
		sel += ", user_id AS ownclouduuid"
	}

	h := &ocHandler{
		options: options,
		logger:  logger,

		hasher: owncloudpassword.NewHasher(&owncloudpassword.Options{}), // TODO make legacy hash configurable

		baseDN:                  strings.ToLower(options.BaseDN),
		allowLocalAnonymousBind: options.AllowLocalAnonymousBind,
		selectSQL:               sel + from,

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
	bindDN = strings.ToLower(bindDN)
	baseDN := strings.ToLower("," + h.options.BaseDN)
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

	filterEntity, err := ldapserver.GetFilterObjectClass(searchReq.Filter)
	if err != nil {
		return ldapserver.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("search error: error parsing filter: %s", searchReq.Filter)
	}

	entries := []*ldap.Entry{}
	switch filterEntity {
	default:
		return ldapserver.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("search error: unhandled filter type: %s [%s]", filterEntity, searchReq.Filter)
	case "posixgroup":
		/*
			groups, err := h.getGroups()
			if err != nil {
				return ldapserver.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, errors.New("search error: error getting groups")
			}
			for _, g := range groups {
				attrs := []*ldap.EntryAttribute{}
				attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{*g.ID}})
				attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s from ownCloud", *g.ID)}})
				//			attrs = append(attrs, &ldap.EntryAttribute{"gidNumber", []string{fmt.Sprintf("%d", g.UnixID)}})
				attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixGroup"}})
				if g.Members != nil {
					members := make([]string, len(g.Members))
					for i, v := range g.Members {
						members[i] = *v.ID
					}

					attrs = append(attrs, &ldap.EntryAttribute{Name: "memberUid", Values: members})
				}
				dn := fmt.Sprintf("cn=%s,%s=groups,%s", *g.ID, h.options.GroupFormat, h.options.BaseDN)
				entries = append(entries, &ldap.Entry{DN: dn, Attributes: attrs})
			}
		*/
	case "posixaccount", "":
		userName := ""
		if searchBaseDN != strings.ToLower(h.options.BaseDN) {
			parts := strings.Split(strings.TrimSuffix(searchBaseDN, baseDN), ",")
			if len(parts) >= 1 {
				userName = strings.TrimPrefix(parts[0], "cn=")
			}
		}
		if userName != "" {
			a, err := h.GetAccountByUsername(h.ctx, userName)
			if err != nil {
				return ldapserver.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, errors.Wrapf(err, "search error: error getting account '%s'", userName)
			}
			e, err := h.accountToEntry(h.ctx, a)
			if err != nil {
				return ldapserver.ServerSearchResult{ResultCode: ldap.LDAPResultOperationsError}, fmt.Errorf("search error: error mapping account to entry")
			}
			entries = append(entries, e)
		} else {
			return ldapserver.ServerSearchResult{ResultCode: ldap.LDAPResultNotSupported}, nil

		}
	}
	return ldapserver.ServerSearchResult{Entries: entries, Referrals: []string{}, Controls: []ldap.Control{}, ResultCode: ldap.LDAPResultSuccess}, nil
}

// Account stores information about accounts.
type Account struct {
	ID           uint64
	Email        sql.NullString
	UserID       string
	DisplayName  sql.NullString
	Quota        sql.NullString
	LastLogin    int
	Backend      string
	Home         string
	State        int8
	PasswordHash string         // from oc_users
	Username     sql.NullString // optional comes from the oc_preferences
	OwnCloudUUID sql.NullString // optional comes from the oc_preferences
}

func (h *ocHandler) accountToEntry(ctx context.Context, a *Account) (*ldap.Entry, error) {
	attrs := []*ldap.EntryAttribute{}
	attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{a.Username.String}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{a.UserID}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "ownclouduuid", Values: []string{a.OwnCloudUUID.String}})
	if a.DisplayName.Valid {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "givenName", Values: []string{a.DisplayName.String}})
	}
	if a.Email.Valid {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{a.Email.String}})
	}

	attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"posixAccount"}})

	attrs = append(attrs, &ldap.EntryAttribute{Name: "description", Values: []string{fmt.Sprintf("%s from ownCloud", a.OwnCloudUUID.String)}})
	//dn := fmt.Sprintf("%s=%s,%s=%s,%s", h.options.NameFormat, *u.ID, h.options.GroupFormat, "users", h.options.BaseDN)
	dn := fmt.Sprintf("%s=%s,%s=%s,%s", "cn", a.Username.String, "cn", "users", h.options.BaseDN)
	return &ldap.Entry{DN: dn, Attributes: attrs}, nil
}
func (h *ocHandler) rowToAccount(ctx context.Context, row Scannable) (*Account, error) {
	a := Account{}
	if err := row.Scan(&a.ID, &a.Email, &a.UserID, &a.DisplayName, &a.Quota, &a.LastLogin, &a.Backend, &a.Home, &a.State, &a.Username, &a.OwnCloudUUID); err != nil {
		//appctx.GetLogger(ctx).Error().Err(err).Msg("could not scan row, skipping")
		return nil, err
	}

	return &a, nil
}

// Scannable describes the interface providing a Scan method
type Scannable interface {
	Scan(...interface{}) error
}

// GetAccountByLogin fetches an account by mail or username
func (h *ocHandler) GetAccountByUsername(ctx context.Context, login string) (*Account, error) {
	var row *sql.Row
	username := strings.ToLower(login) // usernames are lowercased in owncloud classic
	if h.options.JoinUsername {
		row = h.db.QueryRowContext(ctx, h.selectSQL+" WHERE a.lower_user_id=? OR p.configvalue=?", username, login)
	} else {
		row = h.db.QueryRowContext(ctx, h.selectSQL+" WHERE a.lower_user_id=?", username)
	}

	return h.rowToAccount(ctx, row)
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
