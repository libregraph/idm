/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"
)

// Config bundles server configuration settings.
type Config struct {
	Logger logrus.FieldLogger

	LDAPListenAddr string

	LDAPBaseDN                  string
	LDAPAllowLocalAnonymousBind bool

	LDIFMain   string
	LDIFConfig string

	LDIFDefaultCompany    string
	LDIFDefaultMailDomain string
	LDIFTemplateExtraVars map[string]interface{}

	Metrics prometheus.Registerer

	OnReady func(*Server)
}
