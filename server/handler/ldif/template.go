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
	"text/template"
)

func TemplateFuncs(m map[string]interface{}, options *Options) template.FuncMap {
	defaults := map[string]interface{}{
		"Company":    "Default",
		"BaseDN":     "dc=kopano",
		"MailDomain": "kopano.local",
	}
	for k, v := range defaults {
		if _, ok := m[k]; !ok {
			m[k] = v
		}
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

	autoIncrement := uint64(1000)
	if v, ok := m["AutoIncrementMin"]; ok {
		autoIncrement = v.(uint64)
	}

	return template.FuncMap{
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
		"AutoIncrement": func(values ...uint64) uint64 {
			if len(values) > 0 {
				autoIncrement = values[0]
			} else {
				autoIncrement++
			}
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
	}
}
