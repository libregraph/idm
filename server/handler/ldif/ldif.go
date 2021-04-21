/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ldif

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/go-ldap/ldap/v3"
	"github.com/go-ldap/ldif"
	"github.com/spacewander/go-suffix-tree"
)

// parseLDIFFile opens the named file for reading and parses it as LDIF.
func parseLDIFFile(fn string, options *Options) (*ldif.LDIF, error) {
	fn, err := filepath.Abs(fn)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if options.TemplateEngineDisabled {
		return parseLDIF(f, options)
	} else {
		return parseLDIFTemplate(f, options)
	}
}

// parseLDIFTemplate exectues the provided text template and then parses the
// result as LDIF.
func parseLDIFTemplate(r io.Reader, options *Options) (*ldif.LDIF, error) {
	text, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	m := make(map[string]interface{})
	tpl, err := template.New("tpl").Funcs(TemplateFuncs(m, options)).Parse(string(text))
	if err != nil {
		return nil, fmt.Errorf("failed to parse LDIF template: %w", err)
	}

	var buf bytes.Buffer
	err = tpl.Execute(&buf, m)
	if err != nil {
		return nil, fmt.Errorf("failed to process LDIF template: %w", err)
	}

	if options.TemplateDebug {
		fmt.Println("---\n", buf.String(), "\n----")
	}

	return parseLDIF(&buf, options)
}

func parseLDIF(r io.Reader, options *Options) (*ldif.LDIF, error) {
	l := &ldif.LDIF{}
	err := ldif.Unmarshal(r, l)
	if err != nil {
		return nil, err
	}

	return l, nil
}

// treeFromLDIF makes a tree out of the provided LDIF and if index is not nil,
// also indexes each entry in the provided index.
func treeFromLDIF(l *ldif.LDIF, index Index, options *Options) (*suffix.Tree, error) {
	t := suffix.NewTree()

	// NOTE(longsleep): Meh nmcldap vs goldap - for now create the type which we need to return for search.
	var entry *ldap.Entry
	for _, entry = range l.AllEntries() {
		e := &ldifEntry{
			Entry: &ldap.Entry{
				DN: strings.ToLower(entry.DN),
			},
		}
		for _, a := range entry.Attributes {
			switch strings.ToLower(a.Name) {
			case "userpassword":
				e.UserPassword = &ldap.EntryAttribute{
					Name:   a.Name,
					Values: a.Values,
				}
			default:
				e.Entry.Attributes = append(e.Entry.Attributes, &ldap.EntryAttribute{
					Name:   a.Name,
					Values: a.Values,
				})
			}
			if index != nil {
				// Index equality.
				index.Add(a.Name, "eq", a.Values, e)
			}
		}
		v, ok := t.Insert([]byte(e.DN), e)
		if !ok || v != nil {
			return nil, fmt.Errorf("duplicate value: %s", e.DN)
		}
	}

	return t, nil
}
