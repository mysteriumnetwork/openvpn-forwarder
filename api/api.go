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
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
)

type mapping struct {
	IP     string `json:"ip"`
	UserID string `json:"userId"`
}

// NewServer returns new instance of API server
func NewServer(addr string, storage func(ip, userID string)) *Server {
	gin.SetMode(gin.ReleaseMode)
	ginEngine := gin.Default()

	v1 := ginEngine.Group("/api/v1")
	{
		v1.POST("/map", func(c *gin.Context) {
			var m mapping
			c.BindJSON(&m)
			storage(m.IP, m.UserID)
		})
	}

	return &Server{
		Addr: addr,

		ginEngine: ginEngine,
		httpServer: &http.Server{
			Handler: ginEngine,
			Addr:    addr,
		},
	}
}

// Server defines API server with all HTTP endpoints attached to it
type Server struct {
	Addr string

	ginEngine  *gin.Engine
	httpServer *http.Server
}

// Run starts API server
func (server *Server) Run() error {
	return http.ListenAndServe(server.Addr, server.ginEngine)
}

// Stop shutdowns API server
func (server *Server) Stop(ctx context.Context) error {
	return server.httpServer.Shutdown(ctx)
}
