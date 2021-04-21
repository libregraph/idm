/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package server

import (
	"github.com/prometheus/client_golang/prometheus"
	"stash.kopano.io/kgol/kidm/internal/ldapserver"
)

const (
	metricsSubsystemLDAPServer = "ldapserver"
)

// MustRegister registers all rtm metrics with the provided registerer and
// panics upon the first registration that causes an error.
func MustRegister(reg prometheus.Registerer, cs ...prometheus.Collector) {
	reg.MustRegister(cs...)
}

type ldapServerCollector struct {
	stats *ldapserver.Stats

	connsDesc   *prometheus.Desc
	bindsDesc   *prometheus.Desc
	unbindsDesc *prometheus.Desc
	searchesDsc *prometheus.Desc
}

func NewLDAPServerCollector(s *ldapserver.Server) prometheus.Collector {
	return &ldapServerCollector{
		stats: s.Stats,

		connsDesc: prometheus.NewDesc(
			prometheus.BuildFQName("", metricsSubsystemLDAPServer, "connections_total"),
			"Total number of incoming LDAP connections",
			nil,
			nil,
		),
		bindsDesc: prometheus.NewDesc(
			prometheus.BuildFQName("", metricsSubsystemLDAPServer, "binds_total"),
			"Total number of incoming LDAP bind requests",
			nil,
			nil,
		),
		unbindsDesc: prometheus.NewDesc(
			prometheus.BuildFQName("", metricsSubsystemLDAPServer, "unbinds_total"),
			"Total number of incoming LDAP unbind requests",
			nil,
			nil,
		),
		searchesDsc: prometheus.NewDesc(
			prometheus.BuildFQName("", metricsSubsystemLDAPServer, "searches_total"),
			"Total number of incoming LDAP search requests",
			nil,
			nil,
		),
	}
}

// Describe is implemented with DescribeByCollect. That's possible because the
// Collect method will always return the same two metrics with the same two
// descriptors.
func (lc *ldapServerCollector) Describe(ch chan<- *prometheus.Desc) {
	prometheus.DescribeByCollect(lc, ch)
}

// Collect first gathers the associated managers collectors managers data. Then
// it creates constant metrics based on the returned data.
func (lc *ldapServerCollector) Collect(ch chan<- prometheus.Metric) {
	stats := lc.stats.Clone()

	ch <- prometheus.MustNewConstMetric(
		lc.connsDesc,
		prometheus.CounterValue,
		float64(stats.Conns),
	)

	ch <- prometheus.MustNewConstMetric(
		lc.bindsDesc,
		prometheus.CounterValue,
		float64(stats.Binds),
	)

	ch <- prometheus.MustNewConstMetric(
		lc.unbindsDesc,
		prometheus.CounterValue,
		float64(stats.Unbinds),
	)

	ch <- prometheus.MustNewConstMetric(
		lc.searchesDsc,
		prometheus.CounterValue,
		float64(stats.Searches),
	)
}
