/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ldif

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

	"stash.kopano.io/kgol/kidm/server/handler"
)

type ldifHandler struct {
	logger logrus.FieldLogger
	baseDN string

	l *ldif.LDIF
	t *suffix.Tree

	index indexMapRegister
}

type ldifEntry struct {
	*nmcldap.Entry

	userPassword *nmcldap.EntryAttribute
}

func NewLDIFHandler(logger logrus.FieldLogger, fn string, baseDN string) (handler.Handler, error) {
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
	index := newIndexMapRegister()

	// NOTE(longsleep): Meh nmcldap vs goldap - for now create the type which we need to return for search.
	var entry *goldap.Entry
	for _, entry = range l.AllEntries() {
		e := &ldifEntry{
			Entry: &nmcldap.Entry{
				DN: strings.ToLower(entry.DN),
			},
		}
		for _, a := range entry.Attributes {
			switch strings.ToLower(a.Name) {
			case "userpassword":
				e.userPassword = &nmcldap.EntryAttribute{
					Name:   a.Name,
					Values: a.Values,
				}
			default:
				e.Entry.Attributes = append(e.Entry.Attributes, &nmcldap.EntryAttribute{
					Name:   a.Name,
					Values: a.Values,
				})
			}

			// Index equality.
			index.add(a.Name, "eq", a.Values, e)
		}
		v, ok := t.Insert([]byte(e.DN), e)
		if !ok || v != nil {
			return nil, fmt.Errorf("duplicate value: %s", e.DN)
		}
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

		index: index,
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
	entry := entryRecord.(*ldifEntry)

	userPw := entry.userPassword.Values[0]
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
		"controls":       searchReq.Controls,
		"size_limit":     searchReq.SizeLimit,
	})

	logger.Debugf("ldap search request for %s", searchReq.Filter)
	indexFilter, _ := parseFilterToIndexFilter(searchReq.Filter)

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

	controls := []nmcldap.Control{}
	var pagingControl *nmcldap.ControlPaging
	if paging := nmcldap.FindControl(searchReq.Controls, nmcldap.ControlTypePaging); paging != nil {
		pagingControl = paging.(*nmcldap.ControlPaging)
		logger.WithField("paging_size", pagingControl.PagingSize).Warnln("ldap search with paging control not supported")
		pagingControl = nil
	}

	load := true
	var entries []*nmcldap.Entry
	if len(indexFilter) > 0 {
		// Get entries with help of index.
		load = false
		var results [][]*ldifEntry
		for _, f := range indexFilter {
			indexed, found := h.index.load(f[0], f[1], f[2])
			if !found {
				load = true
				break
			}
			results = append(results, indexed)
		}
		if !load {
		results:
			for _, indexed := range results {
				for _, entryRecord := range indexed {
					// NOTE(longsleep): The nmcldap search handler mutates the entries it processes, so we make a copy.
					entry := entryRecord.Entry
					e := &nmcldap.Entry{
						DN:         entry.DN,
						Attributes: make([]*nmcldap.EntryAttribute, len(entry.Attributes)),
					}
					copy(e.Attributes, entry.Attributes)
					entries = append(entries, e)
					if pagingControl != nil && len(entries) >= int(pagingControl.PagingSize) {
						break results
					}
				}
			}
		}
	}
	if load {
		// Walk through all entries (this is slow).
		logger.WithField("filter", searchReq.Filter).Warnln("ldap search filter does not match any index, using slow walk")
		entries = nil
		h.t.WalkSuffix([]byte(searchBaseDN), func(key []byte, entryRecord interface{}) bool {
			// NOTE(longsleep): The nmcldap search handler mutates the entries it processes, so we make a copy.
			entry := entryRecord.(*ldifEntry).Entry
			e := &nmcldap.Entry{
				DN:         entry.DN,
				Attributes: make([]*nmcldap.EntryAttribute, len(entry.Attributes)),
			}
			copy(e.Attributes, entry.Attributes)
			entries = append(entries, e)
			if pagingControl != nil && len(entries) >= int(pagingControl.PagingSize) {
				return true
			}
			return false
		})
	}

	return nmcldap.ServerSearchResult{
		Entries:    entries,
		Referrals:  []string{},
		Controls:   controls,
		ResultCode: nmcldap.LDAPResultSuccess,
	}, nil
}

func (h *ldifHandler) Close(bindDN string, conn net.Conn) error {
	return nil
}
