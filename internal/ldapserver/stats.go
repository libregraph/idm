/*
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * Copyright 2021 Kopano and its licensors
 */

package ldapserver

import (
	"sync"
)

type Stats struct {
	Conns        uint64
	ConnsCurrent uint64
	ConnsMax     uint64
	Binds        uint64
	Unbinds      uint64
	Searches     uint64
	statsMutex   sync.RWMutex
}

func (stats *Stats) countConns(delta uint64) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Conns += delta
		stats.ConnsCurrent += delta
		if stats.ConnsCurrent > stats.ConnsMax {
			stats.ConnsMax = stats.ConnsCurrent
		}
		stats.statsMutex.Unlock()
	}
}

func (stats *Stats) countConnsClose(delta uint64) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.ConnsCurrent -= delta
		stats.statsMutex.Unlock()
	}
}

func (stats *Stats) countBinds(delta uint64) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Binds += delta
		stats.statsMutex.Unlock()
	}
}

func (stats *Stats) countUnbinds(delta uint64) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Unbinds += delta
		stats.statsMutex.Unlock()
	}
}

func (stats *Stats) countSearches(delta uint64) {
	if stats != nil {
		stats.statsMutex.Lock()
		stats.Searches += delta
		stats.statsMutex.Unlock()
	}
}

func (stats *Stats) Clone() *Stats {
	var s2 *Stats
	if stats != nil {
		s2 = &Stats{}
		stats.statsMutex.RLock()
		s2.Conns = stats.Conns
		s2.ConnsCurrent = stats.ConnsCurrent
		s2.Binds = stats.Binds
		s2.Unbinds = stats.Unbinds
		s2.Searches = stats.Searches
		stats.statsMutex.RUnlock()
	}
	return s2
}
