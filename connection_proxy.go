package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

type ConnectionProxy struct {
	sync.Mutex
	port      string
	whitelist []string
	logger    *log.Logger
}

// LogError will write a message to the application log and add the as much
// debug information it can about the connection. It will close the conn
// when it's done with
func (p *ConnectionProxy) LogError(msg, hostname string, conn net.Conn) bool {
	p.logger.Printf("%s\n", NewLogData(msg, "ERROR", hostname, conn))
	if conn != nil {
		p.Close(conn)
	}
	return false
}

// LogDebug have the same behaviour as LogError but only write log lines
// if debugLog has been set to true
func (p *ConnectionProxy) LogDebug(msg, hostname string, conn net.Conn) bool {
	if debugLog {
		p.logger.Printf("%s\n", NewLogData(msg, "DEBUG", hostname, conn))
	}
	if conn != nil {
		p.Close(conn)
	}

	return false
}

// LogAccess will log a successful ACCESS log line to the application log
func (p *ConnectionProxy) LogAccess(hostname string, conn net.Conn) bool {
	p.logger.Printf("%s\n", NewLogData("connected", "ACCESS", hostname, conn))
	return true
}

func (p *ConnectionProxy) Logln(v ...interface{}) {
	p.logger.Println(v...)
}

func (p *ConnectionProxy) Logf(format string, v ...interface{}) {
	p.logger.Printf(format, v...)
}

func (p *ConnectionProxy) Close(c io.Closer) {
	err := c.Close()
	if err != nil {
		p.LogDebug(fmt.Sprintf("Error when closing connection: %s", err), "", nil)
	}
}

func (p *ConnectionProxy) SetWhiteList(list []string) {
	p.Lock()
	p.whitelist = list
	p.Unlock()
}

func (p *ConnectionProxy) GetWhiteList() []string {
	var list []string
	p.Lock()
	for i := range p.whitelist {
		list = append(list, p.whitelist[i])
	}
	p.Unlock()
	return list
}

func (p *ConnectionProxy) IsWhiteListed(hostname string) bool {
	if len(p.whitelist) < 1 {
		return true
	}
	hash := SHA1(hostname)
	for i := range p.whitelist {
		if hash == p.whitelist[i] {
			return true
		}
	}
	return false
}
