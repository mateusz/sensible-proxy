package main

import (
	"fmt"
	"net"
	"time"
)

func NewLogData(msg, msgType, hostname string, conn net.Conn) *LogData {
	return &LogData{
		message:     msg,
		messageType: msgType,
		hostname:    hostname,
		conn:        conn,
	}
}

type LogData struct {
	message     string
	messageType string
	hostname    string
	conn        net.Conn
}

func (data *LogData) String() string {
	remoteIP := "-"
	if data.conn != nil {
		remoteIP = data.conn.RemoteAddr().String()
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
		remoteIP,
		hostname,
		messageType,
		message,
	)
}
