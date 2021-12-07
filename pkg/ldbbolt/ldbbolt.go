/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

// Package ldbbolt provides the lower-level Database functions for managing LDAP Entries
// in a	BoltDB database. Some implementation details:
//
// The database is currently separated in these three buckets
//
// - id2entry: This bucket contains the GOB encoded ldap.Entry instances keyed
//             by a unique 64bit ID
//
// - dn2id: This bucket is used as an index to lookup the ID of an entry by its DN. The DN
//          is used in an normalized (case-folded) form here.
//
// - id2children: This bucket uses the entry-ids as and index and the values contain a list
//                of the entry ids of its direct childdren
//
// Additional buckets will likely be added in the future to create efficient search indexes
package ldbbolt

import (
	"bytes"
	"encoding/binary"
	"encoding/gob"
	"errors"
	"fmt"
	"strings"

	"github.com/go-ldap/ldap/v3"
	"github.com/sirupsen/logrus"
	bolt "go.etcd.io/bbolt"
	"golang.org/x/text/cases"
)

type LdbBolt struct {
	logger  logrus.FieldLogger
	db      *bolt.DB
	options *bolt.Options
	base    string
}

var ErrEntryAlreadyExists = errors.New("entry already exists")

func (bdb *LdbBolt) Configure(logger logrus.FieldLogger, baseDN, dbfile string, options *bolt.Options) error {
	bdb.logger = logger
	logger.Debugf("Open boltdb %s", dbfile)
	db, err := bolt.Open(dbfile, 0o600, options)
	if err != nil {
		bdb.logger.WithError(err).Error("Error opening database")
		return err
	}
	bdb.db = db
	bdb.options = options
	dn, _ := ldap.ParseDN(baseDN)
	bdb.base = NormalizeDN(dn)
	return nil
}

// Initialize() opens the Database file and create the required buckets if they do not
// exist yet. After calling initialize the database is ready to process transactions
func (bdb *LdbBolt) Initialize() error {
	var err error
	if bdb.options == nil || !bdb.options.ReadOnly {
		bdb.logger.Debug("Adding default buckets")
		err = bdb.db.Update(func(tx *bolt.Tx) error {
			_, err = tx.CreateBucketIfNotExists([]byte("dn2id"))
			if err != nil {
				return fmt.Errorf("create bucket 'dn2id': %w", err)
			}
			_, err = tx.CreateBucketIfNotExists([]byte("id2children"))
			if err != nil {
				return fmt.Errorf("create bucket 'dn2id': %w", err)
			}
			_, err = tx.CreateBucketIfNotExists([]byte("id2entry"))
			if err != nil {
				return fmt.Errorf("create bucket 'id2entry': %w", err)
			}
			return nil
		})
		if err != nil {
			bdb.logger.WithError(err).Error("Error creating default buckets")
		}
	}
	return err
}

// While formally some RDN attributes could be casesensitive
// maybe we should just skip the DN parsing and just casefold
// the entire DN string?
func NormalizeDN(dn *ldap.DN) string {
	var nDN string
	caseFold := cases.Fold()
	for r, rdn := range dn.RDNs {
		// FIXME to really normalize multivalued RDNs we'd need
		// to normalize the order of Attributes here as well
		for a, ava := range rdn.Attributes {
			if a > 0 {
				// This is a multivalued RDN.
				nDN += "+"
			} else if r > 0 {
				nDN += ","
			}
			nDN = nDN + caseFold.String(ava.Type) + "=" + caseFold.String(ava.Value)
		}
	}
	return nDN
}

// Performs basic LDAP searches, using the dn2id and id2children buckets to generate
// a list of Result entries. Currently this does strip of the non-request attribute
// Neither does it support LDAP filters. For now we rely on the frontent (LDAPServer)
// to both.
func (bdb *LdbBolt) Search(base string, scope int) ([]*ldap.Entry, error) {
	entries := []*ldap.Entry{}
	dn, _ := ldap.ParseDN(base)
	nDN := NormalizeDN(dn)

	err := bdb.db.View(func(tx *bolt.Tx) error {
		entryID := bdb.GetIDByDN(tx, nDN)
		var entryIDs []uint64
		if entryID == 0 {
			return fmt.Errorf("not found")
		}
		switch scope {
		case ldap.ScopeBaseObject:
			entryIDs = append(entryIDs, entryID)
		case ldap.ScopeSingleLevel:
			entryIDs = bdb.GetChildrenIDs(tx, entryID)
		case ldap.ScopeWholeSubtree:
			entryIDs = append(entryIDs, entryID)
			entryIDs = append(entryIDs, bdb.GetSubtreeIDs(tx, entryID)...)
		}
		id2entry := tx.Bucket([]byte("id2entry"))
		for _, id := range entryIDs {
			entrybytes := id2entry.Get(idToBytes(id))
			buf := bytes.NewBuffer(entrybytes)
			dec := gob.NewDecoder(buf)
			var entry ldap.Entry
			if err := dec.Decode(&entry); err != nil {
				return fmt.Errorf("error decoding entry id: %d, %w", id, err)
			}
			entries = append(entries, &entry)
		}
		return nil
	})
	return entries, err
}

func idToBytes(id uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, id)
	return b
}

func (bdb *LdbBolt) GetChildrenIDs(tx *bolt.Tx, parent uint64) []uint64 {
	bdb.logger.Debugf("GetChildrenIDs '%d'", parent)
	id2Children := tx.Bucket([]byte("id2children"))
	children := id2Children.Get(idToBytes(parent))
	r := bytes.NewReader(children)
	ids := make([]uint64, len(children)/8)
	if err := binary.Read(r, binary.LittleEndian, &ids); err != nil {
		bdb.logger.Error(err)
	}
	bdb.logger.Debugf("Children '%v'\n", ids)
	return ids
}

func (bdb *LdbBolt) GetSubtreeIDs(tx *bolt.Tx, root uint64) []uint64 {
	bdb.logger.Debugf("GetSubtreeIDs '%d'", root)
	var res []uint64
	children := bdb.GetChildrenIDs(tx, root)
	res = append(res, children...)
	for _, child := range children {
		res = append(res, bdb.GetSubtreeIDs(tx, child)...)
	}
	bdb.logger.Debugf("GetSubtreeIDs '%v'", res)
	return res
}

func (bdb *LdbBolt) EntryPut(e *ldap.Entry) error {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(e); err != nil {
		fmt.Printf("%v\n", err)
		panic(err)
	}

	dn, _ := ldap.ParseDN(e.DN)
	parentDN := &ldap.DN{
		RDNs: dn.RDNs[1:],
	}
	nDN := NormalizeDN(dn)

	if !strings.HasSuffix(nDN, bdb.base) {
		return fmt.Errorf("'%s' is not a descendant of '%s'", e.DN, bdb.base)
	}

	nParentDN := NormalizeDN(parentDN)
	err := bdb.db.Update(func(tx *bolt.Tx) error {
		id2entry := tx.Bucket([]byte("id2entry"))
		id := bdb.GetIDByDN(tx, nDN)
		if id != 0 {
			return ErrEntryAlreadyExists
		}
		var err error
		if id, err = id2entry.NextSequence(); err != nil {
			return err
		}

		if err := id2entry.Put(idToBytes(id), buf.Bytes()); err != nil {
			return err
		}
		if nDN != bdb.base {
			if err := bdb.AddID2Children(tx, nParentDN, id); err != nil {
				return err
			}
		}
		dn2id := tx.Bucket([]byte("dn2id"))
		if err := dn2id.Put([]byte(nDN), idToBytes(id)); err != nil {
			return err
		}
		return nil
	})
	return err
}

func (bdb *LdbBolt) AddID2Children(tx *bolt.Tx, nParentDN string, newChildID uint64) error {
	bdb.logger.Debugf("AddID2Children '%s' id '%d'", nParentDN, newChildID)
	parentID := bdb.GetIDByDN(tx, nParentDN)
	if parentID == 0 {
		return fmt.Errorf("parent not found '%s'", nParentDN)
	}

	bdb.logger.Debugf("Parent ID: %v", parentID)

	id2Children := tx.Bucket([]byte("id2children"))

	// FIXME add sanity check here if ID is already present
	children := id2Children.Get(idToBytes(parentID))
	children = append(children, idToBytes(newChildID)...)
	if err := id2Children.Put(idToBytes(parentID), children); err != nil {
		return fmt.Errorf("error updating id2Children index for %d: %w", parentID, err)
	}

	bdb.logger.Debugf("AddID2Children '%d' id '%v'", parentID, children)
	return nil
}

func (bdb *LdbBolt) GetIDByDN(tx *bolt.Tx, nDN string) uint64 {
	dn2id := tx.Bucket([]byte("dn2id"))
	if dn2id == nil {
		bdb.logger.Debugf("Bucket 'dn2id' does not exist")
		return 0
	}
	id := dn2id.Get([]byte(nDN))
	if id == nil {
		bdb.logger.Debugf("DN: '%s' not found", nDN)
		return 0
	}
	return binary.LittleEndian.Uint64(id)
}

func (bdb *LdbBolt) Close() {
	bdb.db.Close()
}
