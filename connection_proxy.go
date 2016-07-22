package main

import (
	"fmt"
	"io"
	"log"
	"net"
)

type ConnectionProxy struct {
	port      string
	whitelist []string
	logger    *log.Logger
}

func (p *ConnectionProxy) LogError(msg, hostname string, conn net.Conn) bool {
	p.logger.Printf("%s\n", NewLogData(msg, "ERROR", hostname, conn))
	if conn != nil {
		p.Close(conn)
	}
	return false
}

func (p *ConnectionProxy) LogAccess(hostname string, conn net.Conn) bool {
	p.logger.Printf("%s\n", NewLogData("connected", "ACCESS", hostname, conn))
	return true
}

func (p *ConnectionProxy) Close(c io.Closer) {
	err := c.Close()
	if err != nil {
		p.LogError(fmt.Sprintf("Error when closing connection: %s", err), "", nil)
	}
}

func (p *ConnectionProxy) IsWhiteListed(hostname string) bool {
	if len(p.whitelist) < 1 {
		return true
	}
	hash := SHA1(hostname)
	for i := range p.whitelist {
		if string(hash) == p.whitelist[i] {
			return true
		}
	}
	return false
}
