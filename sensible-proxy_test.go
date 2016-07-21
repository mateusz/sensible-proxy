package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"testing"
)

type FakeWriter struct {
	logs []byte
}

func (w *FakeWriter) Write(p []byte) (n int, err error) {
	w.logs = append(w.logs, p...)
	return len(p), nil
}

func TestHTTPConnection(t *testing.T) {
	w := &FakeWriter{}
	appLog = log.New(w, "", log.Ldate|log.Ltime)

	actual, conn, _ := requestHTTP("google.com")
	defer conn.Close()

	expected := "HTTP/1.0 302 Found"

	if !strings.Contains(string(actual), expected) {
		t.Errorf("Expected response to contain '%s' got:\n%s", expected, actual)
	}

	expected = "google.com"
	if !strings.Contains(string(w.logs), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, w.logs)
	}
	expected = conn.LocalAddr().String()
	if !strings.Contains(string(w.logs), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, w.logs)
	}
}

func TestHTTPConnectToNoneExistingDNS(t *testing.T) {
	w := &FakeWriter{}
	appLog = log.New(w, "", log.Ldate|log.Ltime)
	content, conn, _ := requestHTTP("t.ls")
	defer conn.Close()
	if string(content) != "" {
		t.Errorf("Expected read to be empty")
	}
	expected := "Couldn't connect to backend"
	if !strings.Contains(string(w.logs), expected) {
		t.Errorf("Expected '%s' in logs, got %s", expected, string(w.logs))
	}
}

func TestHTTPSConnection(t *testing.T) {
	w := &FakeWriter{}
	appLog = log.New(w, "", log.Ldate|log.Ltime)
	actual, conn, err := requestHTTPS("google.com", "google.com")
	defer conn.Close()
	if err != nil {
		t.Errorf("Error on read: %s", err)
		return
	}
	expected := "HTTP/1.0 302 Found"
	if !strings.Contains(string(actual), expected) {
		t.Errorf("Expected response to contain '%s' got:\n%s", expected, actual)
	}

	expected = "google.com"
	if !strings.Contains(string(w.logs), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, w.logs)
	}
	expected = conn.LocalAddr().String()
	if !strings.Contains(string(w.logs), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, w.logs)
	}
}

func TestHTTPSConnectionEmptySNI(t *testing.T) {
	w := &FakeWriter{}
	appLog = log.New(w, "", log.Ldate|log.Ltime)
	_, conn, err := requestHTTPS("", "google.com")

	if conn != nil {
		t.Errorf("Expected connection to be nil")
		conn.Close()
	}

	if err != io.EOF {
		t.Errorf("Expected connection to be closed with an EOF")
	}

	expected := "TLS header parsing problem - no hostname found"
	if !strings.Contains(string(w.logs), expected) {
		t.Errorf("Expected '%s' in logs, got %s", expected, string(w.logs))
	}
}

func TestHTTPSConnectionWrongSNI(t *testing.T) {
	w := &FakeWriter{}
	appLog = log.New(w, "", log.Ldate|log.Ltime)
	actual, conn, err := requestHTTPS("example.com", "google.com")
	defer conn.Close()
	if err != nil {
		t.Errorf("%s", err)
		return
	}

	expected := "HTTP/1.0 404 Not Found"
	if !strings.Contains(string(actual), expected) {
		t.Errorf("Expected response to contain '%s' got:\n%s", expected, actual)
	}

	expected = "example.com"
	if !strings.Contains(string(w.logs), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, w.logs)
	}
	expected = conn.LocalAddr().String()
	if !strings.Contains(string(w.logs), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, w.logs)
	}
}

func requestHTTP(domain string) ([]byte, net.Conn, error) {
	done := make(chan bool)
	defer func(doneChan chan bool) {
		doneChan <- true
	}(done)

	server, err := getProxyServer(done, handleHTTPConnection)
	if err != nil {
		return nil, nil, err
	}
	defer server.Close()

	conn, err := net.Dial("tcp", server.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: "+domain+"\r\nContent-Length: 0\r\n\r\n")
	content, err := ioutil.ReadAll(conn)
	return content, conn, err
}

func requestHTTPS(SNIServerName, requestServerName string) ([]byte, net.Conn, error) {
	done := make(chan bool)
	defer func(doneChan chan bool) {
		doneChan <- true
	}(done)
	listener, err := getProxyServer(done, handleHTTPSConnection)
	if err != nil {
		return nil, nil, err
	}
	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		ServerName: SNIServerName,
	})
	if err != nil {
		return nil, nil, err
	}
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: "+requestServerName+"\r\nContent-Length: 0\r\n\r\n")
	content, err := ioutil.ReadAll(conn)
	return content, conn, err
}

func getProxyServer(done chan bool, handler func(net.Conn)) (net.Listener, error) {
	listener, err := net.Listen("tcp", ":")
	if err != nil {
		return nil, err
	}
	go func(stop chan bool, handler func(net.Conn)) {
		connection, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		handler(connection)
		<-stop
	}(done, handler)

	return listener, nil
}

func TestHTTPSBadInput(t *testing.T) {
	w := &FakeWriter{}
	appLog = log.New(w, "", log.Ldate|log.Ltime)

	var crashers = []string{
		"\x1600\x00",
	}

	for _, crashData := range crashers {
		b := &buffer{}
		b.data = []byte(crashData)
		handleHTTPSConnection(b)
	}
}

// buffer is just here to make it easier to inject random content into a
// connection.
type buffer struct {
	net.TCPConn
	data []byte
}

func (b *buffer) Read(p []byte) (n int, err error) {
	copy(p, b.data)
	return len(b.data), nil
}

func (b *buffer) Close() error {
	return nil
}
