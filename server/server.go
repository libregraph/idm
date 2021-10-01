/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2021 The LibreGraph Authors.
 */

package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/libregraph/idm/pkg/ldapserver"
	"github.com/libregraph/idm/server/handler"
	"github.com/libregraph/idm/server/handler/ldif"
	"github.com/libregraph/idm/server/handler/owncloud"
)

// Server is our server implementation.
type Server struct {
	config *Config

	logger logrus.FieldLogger

	LDAPServer  *ldapserver.Server
	LDAPHandler handler.Handler
}

// NewServer constructs a server from the provided parameters.
func NewServer(c *Config) (*Server, error) {
	s := &Server{
		config: c,

		logger: c.Logger,
	}

	var err error
	switch c.LDAPHandler {
	case "ldif":

		ldifHandlerOptions := &ldif.Options{
			BaseDN:                  s.config.LDAPBaseDN,
			AllowLocalAnonymousBind: s.config.LDAPAllowLocalAnonymousBind,

			DefaultCompany:    s.config.LDIFDefaultCompany,
			DefaultMailDomain: s.config.LDIFDefaultMailDomain,
			TemplateExtraVars: s.config.LDIFTemplateExtraVars,

			TemplateDebug: os.Getenv("KIDM_TEMPLATE_DEBUG") != "",
		}

		s.LDAPHandler, err = ldif.NewLDIFHandler(s.logger, s.config.LDIFMain, ldifHandlerOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create LDIF source handler: %w", err)
		}
		if s.config.LDIFConfig != "" {
			middleware, middlewareErr := ldif.NewLDIFMiddleware(s.logger, s.config.LDIFConfig, ldifHandlerOptions)
			if middlewareErr != nil {
				return nil, fmt.Errorf("failed to create LDIF config handler: %w", middlewareErr)
			}
			s.LDAPHandler = middleware.WithHandler(s.LDAPHandler)
		}
	case "owncloud":
		ocHandlerOptions := &owncloud.Options{
			DSN:                     s.config.OCDatabaseDSN,
			BaseDN:                  s.config.LDAPBaseDN,
			AllowLocalAnonymousBind: s.config.LDAPAllowLocalAnonymousBind,

			DefaultCompany:    s.config.LDIFDefaultCompany,
			DefaultMailDomain: s.config.LDIFDefaultMailDomain,
		}

		s.LDAPHandler, err = owncloud.NewOwnCloudHandler(s.logger, ocHandlerOptions)
		if err != nil {
			return nil, fmt.Errorf("failed to create LDIF source handler: %w", err)
		}
	default:
	}

	s.LDAPServer = ldapserver.NewServer()
	s.LDAPServer.EnforceLDAP = false

	if c.Metrics != nil {
		s.LDAPServer.SetStats(true)
		MustRegister(c.Metrics, NewLDAPServerCollector(s.LDAPServer))
	}

	return s, nil
}

// Serve starts all the accociated servers resources and listeners and blocks
// forever until signals or error occurs.
func (s *Server) Serve(ctx context.Context) error {
	var err error

	serveCtx, serveCtxCancel := context.WithCancel(ctx)
	defer serveCtxCancel()

	logger := s.logger

	errCh := make(chan error, 2)
	exitCh := make(chan struct{}, 1)
	signalCh := make(chan os.Signal, 1)
	readyCh := make(chan struct{}, 1)
	triggerCh := make(chan bool, 1)

	go func() {
		select {
		case <-serveCtx.Done():
			return
		case <-readyCh:
		}
		logger.WithFields(logrus.Fields{}).Infoln("ready")
	}()

	ldapListener, listenErr := net.Listen("tcp", s.config.LDAPListenAddr)
	if listenErr != nil {
		return fmt.Errorf("failed to create LDAP listener: %w", listenErr)
	}

	var serversWg sync.WaitGroup

	// NOTE(longsleep): ldap package uses standard logger. Set standard logger
	// to our logger.
	loggerWriter := logger.WithField("scope", "ldap").WriterLevel(logrus.DebugLevel)
	defer loggerWriter.Close()
	log.SetFlags(0)
	log.SetOutput(loggerWriter)

	ldapHandler := s.LDAPHandler.WithContext(serveCtx)
	s.LDAPServer.BindFunc("", ldapHandler)
	s.LDAPServer.SearchFunc("", ldapHandler)
	s.LDAPServer.CloseFunc("", ldapHandler)

	serversWg.Add(1)
	go func() {
		defer serversWg.Done()
		for {
			select {
			case <-triggerCh:
				reloadErr := ldapHandler.Reload(serveCtx)
				if reloadErr != nil {
					logger.Debugln("reload error: %w", reloadErr)
				} else {
					logger.Debugln("reload complete")
				}
			case <-serveCtx.Done():
				return
			}
		}
	}()

	serversWg.Add(1)
	go func(l net.Listener) {
		defer serversWg.Done()
		logger.WithField("listen_addr", l.Addr()).Infoln("LDAP listener started")
		serveErr := s.LDAPServer.Serve(l)
		if serveErr != nil {
			errCh <- serveErr
		}
	}(ldapListener)

	go func() {
		serversWg.Wait()
		logger.Debugln("server listeners stopped")
		close(exitCh)
	}()

	go func() {
		close(readyCh) // TODO(longsleep): Implement real ready.
		if s.config.OnReady != nil {
			go s.config.OnReady(s)
		}
	}()

	// Wait for exit or error, with support for HUP to reload
	err = func() error {
		signal.Notify(signalCh, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		for {
			select {
			case errFromChannel := <-errCh:
				return errFromChannel
			case reason := <-signalCh:
				if reason == syscall.SIGHUP {
					logger.Infoln("reload signal received")
					select {
					case triggerCh <- true:
					default:
					}
					continue
				}
				logger.WithField("signal", reason).Warnln("received signal")
				return nil
			}
		}
	}()

	// Shutdown, server will stop to accept new connections, requires Go 1.8+.
	logger.Infoln("clean server shutdown start")
	_, shutdownCtxCancel := context.WithTimeout(ctx, 10*time.Second)
	go func() {
		close(s.LDAPServer.Quit)
	}()

	// Cancel our own context,
	serveCtxCancel()
	func() {
		for {
			select {
			case <-exitCh:
				logger.Infoln("clean server shutdown complete, exiting")
				return
			default:
				// Services have not quit yet.
				logger.Info("waiting for services to exit")
			}
			select {
			case reason := <-signalCh:
				logger.WithField("signal", reason).Warn("received signal")
				return
			case <-time.After(100 * time.Millisecond):
			}
		}
	}()
	shutdownCtxCancel() // Prevents leak.

	return err
}
