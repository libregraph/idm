/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package serve

import (
	"context"
	"fmt"
	"os"

	systemDaemon "github.com/coreos/go-systemd/v22/daemon"
	"github.com/spf13/cobra"

	"stash.kopano.io/kgol/kidm/server"
)

var (
	DefaultLogTimestamp  = true
	DefaultLogLevel      = "info"
	DefaultSystemdNotify = false

	DefaultLDAPListenAddr = "127.0.0.1:10389"

	DefaultLDAPBaseDN                  = ""
	DefaultLDAPAllowLocalAnonymousBind = false

	DefaultLDIFMain   = ""
	DefaultLDIFConfig = ""

	DefaultLDIFCompany    = "Default"
	DefaultLDIFMailDomain = "kopano.local"
)

func CommandServe() *cobra.Command {
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

	serveCmd.Flags().BoolVar(&DefaultLogTimestamp, "log-timestamp", DefaultLogTimestamp, "Prefix each log line with timestamp")
	serveCmd.Flags().StringVar(&DefaultLogLevel, "log-level", DefaultLogLevel, "Log level (one of panic, fatal, error, warn, info or debug)")
	serveCmd.Flags().BoolVar(&DefaultSystemdNotify, "systemd-notify", DefaultSystemdNotify, "Enable systemd sd_notify callback")

	serveCmd.Flags().StringVar(&DefaultLDAPListenAddr, "ldap-listen", DefaultLDAPListenAddr, "TCP listen address for LDAP requests")
	serveCmd.Flags().StringVar(&DefaultLDAPBaseDN, "ldap-base-dn", DefaultLDAPBaseDN, "BaseDN for LDAP requests")
	serveCmd.Flags().BoolVar(&DefaultLDAPAllowLocalAnonymousBind, "ldap-allow-local-anonymous", DefaultLDAPAllowLocalAnonymousBind, "Allow anonymous LDAP bind for all local LDAP clients")

	serveCmd.Flags().StringVar(&DefaultLDIFMain, "main-ldif", DefaultLDIFMain, "Path to an LDIF file loaded on startup")
	serveCmd.Flags().StringVar(&DefaultLDIFConfig, "config-ldif", DefaultLDIFConfig, "Path to an LDIF file loaded on startup, this LDIF file is used for bind only")

	serveCmd.Flags().StringVar(&DefaultLDIFCompany, "ldif-default-company", DefaultLDIFCompany, "Sets the default for of the .Company value used in LDIF templates")
	serveCmd.Flags().StringVar(&DefaultLDIFMailDomain, "ldif-default-mail-domain", DefaultLDIFMailDomain, "Set the default value of the .MailDomain value used in LDIF templates")

	return serveCmd
}

func serve(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	logger, err := newLogger(!DefaultLogTimestamp, DefaultLogLevel)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}

	logger.Debugln("serve start")

	cfg := &server.Config{
		Logger: logger,

		LDAPListenAddr: DefaultLDAPListenAddr,

		LDAPBaseDN:                  DefaultLDAPBaseDN,
		LDAPAllowLocalAnonymousBind: DefaultLDAPAllowLocalAnonymousBind,

		LDIFMain:   DefaultLDIFMain,
		LDIFConfig: DefaultLDIFConfig,

		LDIFDefaultCompany:    DefaultLDIFCompany,
		LDIFDefaultMailDomain: DefaultLDIFMailDomain,

		OnReady: func(srv *server.Server) {
			if DefaultSystemdNotify {
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
