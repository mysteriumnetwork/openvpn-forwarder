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

package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type mapping struct {
	IP     string `json:"ip"`
	UserID string `json:"userId"`
}

type stickySaver interface {
	Save(ip string, userID string)
}

type domainTracker interface {
	Dump() map[string]uint64
}

// NewServer returns new instance of API server
func NewServer(addr string, storage stickySaver, dt domainTracker) *http.Server {
	gin.SetMode(gin.ReleaseMode)
	ginEngine := gin.Default()

	ginEngine.GET("/metrics", gin.WrapH(promhttp.Handler()))
	v1 := ginEngine.Group("/api/v1")
	{
		v1.POST("/map", func(c *gin.Context) {
			var m mapping
			c.BindJSON(&m)
			storage.Save(m.IP, m.UserID)
		})
		v1.GET("/domains", func(c *gin.Context) {
			c.JSON(http.StatusOK, dt.Dump())
		})
	}

	return &http.Server{
		Handler: ginEngine,
		Addr:    addr,

		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	}
}
