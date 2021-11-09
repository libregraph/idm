/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package load

import (
	"fmt"
	"os"

	"github.com/go-ldap/ldif"
	"github.com/sirupsen/logrus"

	"github.com/libregraph/idm/pkg/ldbbolt"
)

type LDIFLoader struct {
	logger logrus.FieldLogger
	dbFile string
	baseDN string
}

func NewLDIFLoader(logLevel, dbFile, base string) (*LDIFLoader, error) {
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		return nil, err
	}

	res := &LDIFLoader{
		logger: &logrus.Logger{
			Out:       os.Stderr,
			Formatter: &logrus.TextFormatter{},
			Level:     level,
		},
		dbFile: dbFile,
		baseDN: base,
	}
	return res, nil
}

func (l *LDIFLoader) Load(ldifFile string) error {
	bdb := &ldbbolt.LdbBolt{}

	if err := bdb.Configure(l.logger, l.baseDN, l.dbFile, nil); err != nil {
		return err
	}
	defer bdb.Close()

	if err := bdb.Initialize(); err != nil {
		return err
	}

	f, err := os.Open(ldifFile)
	if err != nil {
		return fmt.Errorf("error opening file '%s': %w", ldifFile, err)
	}
	defer f.Close()
	lf := &ldif.LDIF{}
	err = ldif.Unmarshal(f, lf)
	if err != nil {
		return err
	}

	for _, entry := range lf.AllEntries() {
		l.logger.Debugf("Adding '%s'", entry.DN)
		if err := bdb.EntryPut(entry); err != nil {
			return fmt.Errorf("error adding Entry '%s': %w", entry.DN, err)
		}
	}
	return nil
}
