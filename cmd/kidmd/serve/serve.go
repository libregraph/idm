/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package serve

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	_ "net/http/pprof" // Include pprof for debugging, its only enabled when --with-pprof is given.
	"os"
	"runtime"

	systemDaemon "github.com/coreos/go-systemd/v22/daemon"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/libregraph/idm/server"
)

var (
	DefaultLogTimestamp  = true
	DefaultLogLevel      = "info"
	DefaultSystemdNotify = false

	DefaultLDAPListenAddr = "127.0.0.1:10389"

	DefaultLDAPBaseDN                  = "dc=kopano,dc=local"
	DefaultLDAPAllowLocalAnonymousBind = false

	DefaultLDIFMain   = os.Getenv("KIDMD_DEFAULT_LDIF_MAIN_PATH")
	DefaultLDIFConfig = os.Getenv("KIDMD_DEFAULT_LDIF_CONFIG_PATH")

	DefaultLDIFCompany    = "Default"
	DefaultLDIFMailDomain = "kopano.local"

	DefaultWithPprof       = false
	DefaultPprofListenAddr = "127.0.0.1:6060"

	DefaultWithMetrics       = false
	DefaultMetricsListenAddr = "127.0.0.1:6389"
)

func init() {
	envDefaultLDAPBaseDN := os.Getenv("KIDMD_DEFAULT_LDAP_BASEDN")
	if envDefaultLDAPBaseDN != "" {
		DefaultLDAPBaseDN = envDefaultLDAPBaseDN
	}

	envDefaultLDAPListenAddr := os.Getenv("KIDMD_DEFAULT_LDAP_LISTEN")
	if envDefaultLDAPListenAddr != "" {
		DefaultLDAPListenAddr = envDefaultLDAPListenAddr
	}

	envDefaultLDIFCompany := os.Getenv("KIDMD_DEFAULT_LDIF_TEMPLATE_COMPANY")
	if envDefaultLDIFCompany != "" {
		DefaultLDIFCompany = envDefaultLDIFCompany
	}

	envDefaultLDIFMailDomain := os.Getenv("KIDMD_DEFAULT_LDIF_TEMPLATE_MAIL_DOMAIN")
	if envDefaultLDIFMailDomain != "" {
		DefaultLDIFMailDomain = envDefaultLDIFMailDomain
	}
}

func CommandServe() *cobra.Command {
	serveCmd := &cobra.Command{
		Use:   "serve [...args]",
		Short: "Start service",
		Run: func(cmd *cobra.Command, args []string) {
			if err := serve(cmd, args); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				var exitCodeErr *ErrorWithExitCode
				if errors.As(err, &exitCodeErr) {
					os.Exit(exitCodeErr.Code)
				} else {
					os.Exit(1)
				}
			}
		},
	}

	serveCmd.Flags().BoolVar(&DefaultLogTimestamp, "log-timestamp", DefaultLogTimestamp, "Prefix each log line with timestamp")
	serveCmd.Flags().StringVar(&DefaultLogLevel, "log-level", DefaultLogLevel, "Log level (one of panic, fatal, error, warn, info or debug)")
	serveCmd.Flags().BoolVar(&DefaultSystemdNotify, "systemd-notify", DefaultSystemdNotify, "Enable systemd sd_notify callback")

	serveCmd.Flags().StringVar(&DefaultLDAPListenAddr, "ldap-listen", DefaultLDAPListenAddr, "TCP listen address for LDAP requests")
	serveCmd.Flags().StringVar(&DefaultLDAPBaseDN, "ldap-base-dn", DefaultLDAPBaseDN, "BaseDN for LDAP requests")
	serveCmd.Flags().BoolVar(&DefaultLDAPAllowLocalAnonymousBind, "ldap-allow-local-anonymous", DefaultLDAPAllowLocalAnonymousBind, "Allow anonymous LDAP bind for all local LDAP clients")

	serveCmd.Flags().StringVar(&DefaultLDIFMain, "ldif-main", DefaultLDIFMain, "Path to a LDIF file or .d folder containing LDIF files")
	serveCmd.Flags().StringVar(&DefaultLDIFConfig, "ldif-config", DefaultLDIFConfig, "Path to a LDIF file for entries used only for bind")

	serveCmd.Flags().StringVar(&DefaultLDIFCompany, "ldif-template-default-company", DefaultLDIFCompany, "Sets the default for of the .Company value used in LDIF templates")
	serveCmd.Flags().StringVar(&DefaultLDIFMailDomain, "ldif-template-default-mail-domain", DefaultLDIFMailDomain, "Set the default value of the .MailDomain value used in LDIF templates")

	serveCmd.Flags().BoolVar(&DefaultWithPprof, "with-pprof", DefaultWithPprof, "With pprof enabled")
	serveCmd.Flags().StringVar(&DefaultPprofListenAddr, "pprof-listen", DefaultPprofListenAddr, "TCP listen address for pprof")

	serveCmd.Flags().BoolVar(&DefaultWithMetrics, "with-metrics", DefaultWithMetrics, "Enable metrics")
	serveCmd.Flags().StringVar(&DefaultMetricsListenAddr, "metrics-listen", DefaultMetricsListenAddr, "TCP listen address for metrics")

	return serveCmd
}

func serve(cmd *cobra.Command, args []string) error {
	bs := &bootstrap{}
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
	}()

	err := bs.configure(ctx, cmd, args)
	if err != nil {
		return StartupError(err)
	}

	return bs.srv.Serve(ctx)
}

type bootstrap struct {
	logger logrus.FieldLogger

	srv *server.Server
}

func (bs *bootstrap) configure(ctx context.Context, cmd *cobra.Command, args []string) error {
	logger, err := newLogger(!DefaultLogTimestamp, DefaultLogLevel)
	if err != nil {
		return fmt.Errorf("failed to create logger: %w", err)
	}
	bs.logger = logger

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

	// Metrics support.
	if DefaultWithMetrics && DefaultMetricsListenAddr != "" {
		metricsRegistry := prometheus.NewPedanticRegistry()
		cfg.Metrics = prometheus.WrapRegistererWithPrefix("kidm_", metricsRegistry)

		// Add the standard process and Go metrics to the custom registry.
		metricsRegistry.MustRegister(
			prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}),
			prometheus.NewGoCollector(),
		)
		go func() {
			handler := http.NewServeMux()
			logger.WithField("listenAddr", DefaultMetricsListenAddr).Infoln("metrics enabled, starting listener")
			handler.Handle("/metrics", promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{}))
			if listenErr := http.ListenAndServe(DefaultMetricsListenAddr, handler); listenErr != nil {
				logger.WithError(listenErr).Errorln("unable to start metrics listener")
			}
		}()
	}

	bs.srv, err = server.NewServer(cfg)
	if err != nil {
		return err
	}

	// Profiling support.
	withPprof, _ := cmd.Flags().GetBool("with-pprof")
	pprofListenAddr, _ := cmd.Flags().GetString("pprof-listen")
	if withPprof && pprofListenAddr != "" {
		runtime.SetMutexProfileFraction(5)
		go func() {
			pprofListen := pprofListenAddr
			logger.WithField("listenAddr", pprofListen).Infoln("pprof enabled, starting listener")
			if listenErr := http.ListenAndServe(pprofListen, nil); listenErr != nil {
				logger.WithError(listenErr).Errorln("unable to start pprof listener")
			}
		}()
	}

	return nil
}
