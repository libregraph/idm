/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ldif

import (
	"bytes"
	"encoding/base64"
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
	m := map[string]interface{}{
		"Company":    "Default",
		"BaseDN":     "dc=kopano",
		"MailDomain": "kopano.local",
	}
	if options != nil {
		if options.BaseDN != "" {
			m["BaseDN"] = options.BaseDN
		}
		if options.DefaultCompany != "" {
			m["Company"] = options.DefaultCompany
		}
		if options.DefaultMailDomain != "" {
			m["MailDomain"] = options.DefaultMailDomain
		}
		for k, v := range options.TemplateExtraVars {
			m[k] = v
		}
	}

	autoIncrement := 1000
	tpl, err := template.New("tpl").Funcs(template.FuncMap{
		"WithCompany": func(value string) string {
			m["Company"] = value
			return ""
		},
		"WithBaseDN": func(value string) string {
			m["BaseDN"] = value
			return ""
		},
		"WithMailDomain": func(value string) string {
			m["MailDomain"] = value
			return ""
		},
		"AutoIncrement": func() int {
			autoIncrement++
			return autoIncrement
		},
		"formatAsBase64": func(s string) string {
			return base64.StdEncoding.EncodeToString([]byte(s))
		},
		"formatAsFileBase64": func(fn string) (string, error) {
			fn, err := filepath.Abs(fn)
			if err != nil {
				return "", err
			}

			f, err := os.Open(fn)
			if err != nil {
				return "", fmt.Errorf("LDIF template fromFile open failed with error: %w", err)
			}
			defer f.Close()

			reader := io.LimitReader(f, 1024*1024+1)

			var buf bytes.Buffer
			encoder := base64.NewEncoder(base64.StdEncoding, &buf)
			n, err := io.Copy(encoder, reader)
			if err != nil {
				return "", fmt.Errorf("LDIF template fromFile error: %w", err)
			}
			if n > 1024*1024 {
				return "", fmt.Errorf("LDIF template fromFile size limit exceeded: %s", fn)
			}

			return buf.String(), nil
		},
	}).ParseFiles(fn)
	if err != nil {
		return nil, fmt.Errorf("failed to parse LDIF template: %w", err)
	}

	var buf bytes.Buffer
	err = tpl.ExecuteTemplate(&buf, filepath.Base(fn), m)
	if err != nil {
		return nil, fmt.Errorf("failed to process LDIF template: %w", err)
	}

	if false {
		fmt.Println(buf.String())
	}

	l := &ldif.LDIF{}
	err = ldif.Unmarshal(&buf, l)
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
