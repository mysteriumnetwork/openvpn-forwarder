/*
 * Copyright (C) 2019 The "MysteriumNetwork/openvpn-forwarder" Authors.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package proxy

import (
	"crypto/sha256"
	"encoding/base64"
	"log"

	"github.com/tidwall/buntdb"
)

const (
	// MemoryStorage describes in-memory data storage.
	MemoryStorage = ":memory:"
)

type stickyMapper struct {
	cache *buntdb.DB
}

// NewStickyMapper creates database for storing IP to UserID mapping.
func NewStickyMapper(path string) (*stickyMapper, error) {
	db, err := buntdb.Open(path)
	return &stickyMapper{
		cache: db,
	}, err
}

// Save creates or updated IP to UserID mapping.
func (sm *stickyMapper) Save(ip, userID string) {
	hashSum := sha256.Sum256([]byte(userID))
	err := sm.cache.Update(func(tx *buntdb.Tx) error {
		_, _, err := tx.Set(ip, base64.URLEncoding.EncodeToString(hashSum[:]), nil)
		return err
	})

	log.Fatalln("Saving stickyness mapping: ", ip, userID)

	if err != nil {
		log.Println("Failed to save IP to UserID mapping: ", err)
	}
}

// Hash returns hashed UserID by current IP address.
func (sm *stickyMapper) Hash(ip string) (hash string) {
	err := sm.cache.View(func(tx *buntdb.Tx) (err error) {
		hash, err = tx.Get(ip)
		return err
	})

	if err == nil {
		return hash
	}

	log.Println("Failed to load IP to UserID mapping: ", ip, err)
	log.Println("Falling back to IP-stickiness")
	hashSum := sha256.Sum256([]byte(ip))
	return base64.URLEncoding.EncodeToString(hashSum[:])
}
