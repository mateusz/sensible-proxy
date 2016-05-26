package main

import (
	"fmt"
	"net"
	"time"
)

type LogData struct {
	message     string
	messageType string
	hostname    string
	conn        net.Conn
}

func (data *LogData) String() string {
	remoteIp := "-"
	if data.conn != nil {
		remoteIp = data.conn.RemoteAddr().String()
	}
	hostname := "-"
	message := "-"
	messageType := ""
	if data.messageType != "" {
		messageType = fmt.Sprintf("%s:", data.messageType)
	}
	if data.hostname != "" {
		hostname = data.hostname
	}
	if data.message != "" {
		message = data.message
	}

	return fmt.Sprintf(
		"%s %s %s %s %s",
		time.Now().Format(time.RFC3339),
		remoteIp,
		hostname,
		messageType,
		message,
	)
}
