/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ldif

type Options struct {
	BaseDN                  string
	AllowLocalAnonymousBind bool

	DefaultCompany    string
	DefaultMailDomain string

	TemplateExtraVars      map[string]interface{}
	TemplateEngineDisabled bool
	TemplateDebug          bool

	templateBasePath string
}
