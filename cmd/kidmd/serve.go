/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package main

import (
	"context"
	"fmt"
	"os"

	systemDaemon "github.com/coreos/go-systemd/v22/daemon"
	"github.com/spf13/cobra"

	"stash.kopano.io/kgol/kidm/server"
)

var (
	defaultLogTimestamp  = true
	defaultLogLevel      = "info"
	defaultSystemdNotify = false

	defaultLDAPListenAddr = "127.0.0.1:10389"

	defaultLDAPBaseDN                  = ""
	defaultLDAPAllowLocalAnonymousBind = false

	defaultLDIFMain   = ""
	defaultLDIFConfig = ""

	defaultLDIFCompany    = "Default"
	defaultLDIFMailDomain = "kopano.local"
)

func commandServe() *cobra.Command {
	serveCmd := &cobra.Command{
		Use:   "serve [...args]",
		Short: "Start service",
		Run: func(cmd *cobra.Command, args []string) {
			if err := serve(cmd, args); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	serveCmd.Flags().BoolVar(&defaultLogTimestamp, "log-timestamp", defaultLogTimestamp, "Prefix each log line with timestamp")
	serveCmd.Flags().StringVar(&defaultLogLevel, "log-level", defaultLogLevel, "Log level (one of panic, fatal, error, warn, info or debug)")
	serveCmd.Flags().BoolVar(&defaultSystemdNotify, "systemd-notify", defaultSystemdNotify, "Enable systemd sd_notify callback")

	serveCmd.Flags().StringVar(&defaultLDAPListenAddr, "ldap-listen", defaultLDAPListenAddr, "TCP listen address for LDAP requests")
	serveCmd.Flags().StringVar(&defaultLDAPBaseDN, "ldap-base-dn", defaultLDAPBaseDN, "BaseDN for LDAP requests")
	serveCmd.Flags().BoolVar(&defaultLDAPAllowLocalAnonymousBind, "ldap-allow-local-anonymous", defaultLDAPAllowLocalAnonymousBind, "Allow anonymous LDAP bind for all local LDAP clients")

	serveCmd.Flags().StringVar(&defaultLDIFMain, "main-ldif", defaultLDIFMain, "Path to an LDIF file loaded on startup")
	serveCmd.Flags().StringVar(&defaultLDIFConfig, "config-ldif", defaultLDIFConfig, "Path to an LDIF file loaded on startup, this LDIF file is used for bind only")

	serveCmd.Flags().StringVar(&defaultLDIFCompany, "ldif-default-company", defaultLDIFCompany, "Sets the default for of the .Company value used in LDIF templates")
	serveCmd.Flags().StringVar(&defaultLDIFMailDomain, "ldif-default-mail-domain", defaultLDIFMailDomain, "Set the default value of the .MailDomain value used in LDIF templates")

	return serveCmd
}

func serve(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	logger, err := newLogger(!defaultLogTimestamp, defaultLogLevel)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	logger.Debugln("serve start")

	cfg := &server.Config{
		Logger: logger,

		LDAPListenAddr: defaultLDAPListenAddr,

		LDAPBaseDN:                  defaultLDAPBaseDN,
		LDAPAllowLocalAnonymousBind: defaultLDAPAllowLocalAnonymousBind,

		LDIFMain:   defaultLDIFMain,
		LDIFConfig: defaultLDIFConfig,

		OnReady: func(srv *server.Server) {
			if defaultSystemdNotify {
				ok, notifyErr := systemDaemon.SdNotify(false, systemDaemon.SdNotifyReady)
				logger.WithField("ok", ok).Debugln("called systemd sd_notify ready")
				if notifyErr != nil {
					logger.WithError(notifyErr).Errorln("failed to trigger systemd sd_notify")
				}
			}
		},
	}

	srv, err := server.NewServer(cfg)
	if err != nil {
		return err
	}

	return srv.Serve(ctx)
}
