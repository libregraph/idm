/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ldif

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	cmap "github.com/orcaman/concurrent-map"
	"github.com/sirupsen/logrus"
	"github.com/spacewander/go-suffix-tree"
	"stash.kopano.io/kgol/rndm"

	"stash.kopano.io/kgol/kidm/internal/ldapserver"
	"stash.kopano.io/kgol/kidm/server/handler"
)

type ldifHandler struct {
	ctx    context.Context
	logger logrus.FieldLogger

	baseDN                  string
	allowLocalAnonymousBind bool

	l *ldif.LDIF
	t *suffix.Tree

	index Index

	activeSearchPagings cmap.ConcurrentMap
}

var _ handler.Handler = (*ldifHandler)(nil) // Verify that *ldifHandler implements handler.Handler.

func NewLDIFHandler(ctx context.Context, logger logrus.FieldLogger, fn string, options *Options) (handler.Handler, error) {
	if fn == "" {
		return nil, fmt.Errorf("file name is empty")
	}
	if options.BaseDN == "" {
		return nil, fmt.Errorf("base dn is empty")
	}

	l, err := parseLDIFFile(fn, options)
	if err != nil {
		return nil, err
	}

	index := newIndexMapRegister()
	t, err := treeFromLDIF(l, index, options)
	if err != nil {
		return nil, err
	}
	logger.WithFields(logrus.Fields{
		"version":       l.Version,
		"entries_count": len(l.Entries),
		"tree_length":   t.Len(),
		"base_dn":       options.BaseDN,
	}).Debugln("loaded LDIF from file")

	return &ldifHandler{
		ctx:    ctx,
		logger: logger,

		baseDN:                  strings.ToLower(options.BaseDN),
		allowLocalAnonymousBind: options.AllowLocalAnonymousBind,

		l: l,
		t: t,

		index: index,

		activeSearchPagings: cmap.New(),
	}, nil
}

func (h *ldifHandler) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldapserver.LDAPResultCode, error) {
	bindDN = strings.ToLower(bindDN)

	logger := h.logger.WithFields(logrus.Fields{
		"bind_dn":     bindDN,
		"remote_addr": conn.RemoteAddr().String(),
	})

	if err := h.validateBindDN(bindDN, conn); err != nil {
		logger.WithError(err).Debugln("ldap bind request BindDN validation failed")
		return ldap.LDAPResultInsufficientAccessRights, nil
	}

	if bindDN == "" {
		logger.Debugf("ldap anonymous bind request")
		if bindSimplePw == "" {
			return ldap.LDAPResultSuccess, nil
		} else {
			return ldap.LDAPResultInvalidCredentials, nil
		}
	} else {
		logger.Debugf("ldap bind request")
	}

	entryRecord, found := h.t.Get([]byte(bindDN))
	if !found {
		err := fmt.Errorf("user not found")
		logger.WithError(err).Debugf("ldap bind error")
		return ldap.LDAPResultInvalidCredentials, nil
	}
	entry := entryRecord.(*ldifEntry)

	if err := entry.validatePassword(bindSimplePw); err != nil {
		logger.WithError(err).Debugf("ldap bind credentials error")
		return ldap.LDAPResultInvalidCredentials, nil
	}
	return ldap.LDAPResultSuccess, nil
}

func (h *ldifHandler) Search(bindDN string, searchReq *ldap.SearchRequest, conn net.Conn) (ldapserver.ServerSearchResult, error) {
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

	indexFilter, _ := parseFilterToIndexFilter(searchReq.Filter)

	if !strings.HasSuffix(searchBaseDN, h.baseDN) {
		err := fmt.Errorf("ldap search BaseDN is not in our BaseDN %s", h.baseDN)
		return ldapserver.ServerSearchResult{
			ResultCode: ldap.LDAPResultInsufficientAccessRights,
		}, err
	}

	doneControls := []ldap.Control{}
	var pagingControl *ldap.ControlPaging
	var pagingCookie []byte
	if paging := ldap.FindControl(searchReq.Controls, ldap.ControlTypePaging); paging != nil {
		pagingControl = paging.(*ldap.ControlPaging)
		if searchReq.SizeLimit > 0 && pagingControl.PagingSize >= uint32(searchReq.SizeLimit) {
			pagingControl = nil
		} else {
			pagingCookie = pagingControl.Cookie
		}
	}

	pumpCh, resultCode := func() (<-chan *ldifEntry, ldapserver.LDAPResultCode) {
		var pumpCh chan *ldifEntry
		var start = true
		if pagingControl != nil {
			if len(pagingCookie) == 0 {
				pagingCookie = []byte(base64.RawStdEncoding.EncodeToString(rndm.GenerateRandomBytes(8)))
				pagingControl.Cookie = pagingCookie
				pumpCh = make(chan *ldifEntry)
				h.activeSearchPagings.Set(string(pagingControl.Cookie), pumpCh)
				logger.WithField("paging_cookie", string(pagingControl.Cookie)).Debugln("ldap search paging pump start")
			} else {
				pumpChRecord, ok := h.activeSearchPagings.Get(string(pagingControl.Cookie))
				if !ok {
					return nil, ldap.LDAPResultUnwillingToPerform
				}
				if pagingControl.PagingSize > 0 {
					logger.WithField("paging_cookie", string(pagingControl.Cookie)).Debugln("ldap search paging pump continue")
					pumpCh = pumpChRecord.(chan *ldifEntry)
					start = false
				} else {
					// No paging size with cookie, means abandon.
					start = false
					logger.WithField("paging_cookie", string(pagingControl.Cookie)).Debugln("search paging pump abandon")
					// TODO(longsleep): Cancel paging pump context.
					h.activeSearchPagings.Remove(string(pagingControl.Cookie))
				}
			}
		} else {
			pumpCh = make(chan *ldifEntry)
		}
		if start {
			go h.searchEntriesPump(h.ctx, pumpCh, searchReq, pagingControl, indexFilter)
		}

		return pumpCh, ldap.LDAPResultSuccess
	}()
	if resultCode != ldap.LDAPResultSuccess {
		err := fmt.Errorf("search unable to perform: %d", resultCode)
		return ldapserver.ServerSearchResult{
			ResultCode: resultCode,
		}, err
	}

	filterPacket, err := ldapserver.CompileFilter(searchReq.Filter)
	if err != nil {
		return ldapserver.ServerSearchResult{
			ResultCode: ldap.LDAPResultOperationsError,
		}, err
	}

	var entryRecord *ldifEntry
	var entries []*ldap.Entry
	var entry *ldap.Entry
	var count uint32
	var keep bool
results:
	for {
		select {
		case entryRecord = <-pumpCh:
			if entryRecord == nil {
				// All done, set cookie to empty.
				pagingCookie = []byte{}
				break results

			} else {
				entry = entryRecord.Entry

				// Apply filter.
				keep, resultCode = ldapserver.ServerApplyFilter(filterPacket, entry)
				if resultCode != ldap.LDAPResultSuccess {
					return ldapserver.ServerSearchResult{
						ResultCode: resultCode,
					}, errors.New("search filter apply error")
				}
				if !keep {
					continue
				}

				// Filter scope.
				keep, resultCode = ldapserver.ServerFilterScope(searchReq.BaseDN, searchReq.Scope, entry)
				if resultCode != ldap.LDAPResultSuccess {
					return ldapserver.ServerSearchResult{
						ResultCode: resultCode,
					}, errors.New("search scope apply error")
				}
				if !keep {
					continue
				}

				// Make a copy, before filtering attributes.
				e := &ldap.Entry{
					DN:         entry.DN,
					Attributes: make([]*ldap.EntryAttribute, len(entry.Attributes)),
				}
				copy(e.Attributes, entry.Attributes)

				// Filter attributes from entry.
				resultCode, err = ldapserver.ServerFilterAttributes(searchReq.Attributes, e)
				if err != nil {
					return ldapserver.ServerSearchResult{
						ResultCode: resultCode,
					}, err
				}

				// Append entry as result.
				entries = append(entries, e)

				// Count and more.
				count++
				if pagingControl != nil {
					if count >= pagingControl.PagingSize {
						break results
					}
				}
				if searchReq.SizeLimit > 0 && count >= uint32(searchReq.SizeLimit) {
					// TODO(longsleep): handle total sizelimit for paging.
					break results
				}
			}
		}
	}

	if pagingControl != nil {
		doneControls = append(doneControls, &ldap.ControlPaging{
			PagingSize: 0,
			Cookie:     pagingCookie,
		})
	}

	return ldapserver.ServerSearchResult{
		Entries:    entries,
		Referrals:  []string{},
		Controls:   doneControls,
		ResultCode: ldap.LDAPResultSuccess,
	}, nil
}

func (h *ldifHandler) searchEntriesPump(ctx context.Context, pumpCh chan<- *ldifEntry, searchReq *ldap.SearchRequest, pagingControl *ldap.ControlPaging, indexFilter [][]string) {
	defer func() {
		if pagingControl != nil {
			h.activeSearchPagings.Remove(string(pagingControl.Cookie))
			close(pumpCh)
			h.logger.WithField("paging_cookie", string(pagingControl.Cookie)).Debugln("ldap search paging pump ended")
		} else {
			close(pumpCh)
		}
	}()

	pump := func(entryRecord *ldifEntry) bool {
		select {
		case pumpCh <- entryRecord:
		case <-ctx.Done():
			h.logger.WithField("paging_cookie", string(pagingControl.Cookie)).Warnln("ldap search paging pump context done")
			return false
		case <-time.After(1 * time.Minute):
			h.logger.WithField("paging_cookie", string(pagingControl.Cookie)).Warnln("ldap search paging pump timeout")
			return false
		}
		return true
	}

	load := true
	if len(indexFilter) > 0 {
		// Get entries with help of index.
		load = false
		var results []*[]*ldifEntry
		for _, f := range indexFilter {
			indexed, found := h.index.Load(f[0], f[1], f[2])
			if !found {
				load = true
				break
			}
			results = append(results, &indexed)
		}
		if !load {
			for _, indexed := range results {
				for _, entryRecord := range *indexed {
					if ok := pump(entryRecord); !ok {
						return
					}
				}
			}
		}
	}
	if load {
		// Walk through all entries (this is slow).
		h.logger.WithField("filter", searchReq.Filter).Warnln("ldap search filter does not match any index, using slow walk")
		searchBaseDN := strings.ToLower(searchReq.BaseDN)
		h.t.WalkSuffix([]byte(searchBaseDN), func(key []byte, entryRecord interface{}) bool {
			if ok := pump(entryRecord.(*ldifEntry)); !ok {
				return true
			}
			return false
		})
	}
}

func (h *ldifHandler) validateBindDN(bindDN string, conn net.Conn) error {
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

func (h *ldifHandler) Close(bindDN string, conn net.Conn) error {
	return nil
}
