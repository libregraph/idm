/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package owncloud

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	// Provides mysql drivers
	"github.com/go-ldap/ldap/v3"
	_ "github.com/go-sql-driver/mysql"
)

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
	attrs = append(attrs, &ldap.EntryAttribute{Name: "uid", Values: []string{a.UserID}})
	attrs = append(attrs, &ldap.EntryAttribute{Name: "ownclouduuid", Values: []string{a.OwnCloudUUID.String}})
	if a.DisplayName.Valid {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "cn", Values: []string{a.DisplayName.String}})
	}
	if a.Email.Valid {
		attrs = append(attrs, &ldap.EntryAttribute{Name: "mail", Values: []string{a.Email.String}})
	}

	// we do not need to return MUST attributes from the schemas, eg. sn for "organizationalPerson" because every LDAP server might have an acl
	// TODO spec out objectclass "ownCloud"

	attrs = append(attrs, &ldap.EntryAttribute{Name: "objectClass", Values: []string{"top", "person", "organizationalPerson", "inetOrgPerson", "ownCloud"}})

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
	selectSQL := "SELECT id, email, user_id, display_name, quota, last_login, backend, home, state"
	fromSQL := " FROM oc_accounts"
	if h.options.JoinUsername {
		selectSQL += ", p.configvalue AS username"
		fromSQL += ` LEFT JOIN oc_preferences p
						ON a.user_id=p.userid
						AND p.appid='core'
						AND p.configkey='username'`
		row = h.db.QueryRowContext(ctx, selectSQL+fromSQL+" WHERE a.lower_user_id=? OR p.configvalue=?", username, login)
	} else {
		row = h.db.QueryRowContext(ctx, selectSQL+fromSQL+" WHERE a.lower_user_id=?", username)
	}

	return h.rowToAccount(ctx, row)
}

func (h *ocHandler) GetAccountCount() (count uint64) {
	row := h.db.QueryRowContext(h.ctx, "SELECT count(*) FROM oc_accounts")
	if err := row.Scan(&count); err != nil {
		h.logger.WithError(err).Error("could not count accounts")
	}
	return
}
func (h *ocHandler) GetGroupCount() (count uint64) {
	row := h.db.QueryRowContext(h.ctx, "SELECT count(*) FROM oc_groups")
	if err := row.Scan(&count); err != nil {
		h.logger.WithError(err).Error("could not count groups")
	}
	return
}
