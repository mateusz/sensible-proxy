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
	"sync"
)

type FakeWriter struct {
	sync.Mutex
	logs []byte
}

func (w *FakeWriter) Write(p []byte) (n int, err error) {
	w.Lock()
	defer w.Unlock()
	w.logs = append(w.logs, p...)
	return len(p), nil
}

func (w *FakeWriter) Read() []byte {
	w.Lock()
	defer w.Unlock()
	temp := make([]byte, len(w.logs))
	copy(temp, w.logs)
	return temp
}

func TestHTTPConnection(t *testing.T) {
	w := &FakeWriter{}
	appLog = log.New(w, "", log.Ldate|log.Ltime)

	actual, conn, err := requestHTTP("google.com")
	if err != nil {
		t.Errorf("%s\n", err)
		return
	}
	defer conn.Close()

	// depending on the area you are testing from you might get a 301 or 302
	expected := "HTTP/1.0 30"

	if !strings.Contains(string(actual), expected) {
		t.Errorf("Expected response to contain '%s' got:\n%s", expected, actual)
	}

	logLines := w.Read()
	expected = "google.com"
	if !strings.Contains(string(logLines), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, w.logs)
	}
	expected = conn.LocalAddr().String()
	if !strings.Contains(string(logLines), expected) {
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
	logLines := w.Read()
	expected := "Couldn't connect to backend"
	if !strings.Contains(string(logLines), expected) {
		t.Errorf("Expected '%s' in logs, got %s", expected, string(logLines))
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

	// depending on the area you are testing from you might get a 301 or 302
	expected := "HTTP/1.0 30"

	if !strings.Contains(string(actual), expected) {
		t.Errorf("Expected response to contain '%s' got:\n%s", expected, actual)
	}

	logLines := w.Read()
	expected = "google.com"
	if !strings.Contains(string(logLines), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, string(logLines))
	}
	expected = conn.LocalAddr().String()
	if !strings.Contains(string(logLines), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, string(logLines))
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
	logLines := w.Read()
	expected := "TLS header parsing problem - no hostname found"
	if !strings.Contains(string(logLines), expected) {
		t.Errorf("Expected '%s' in logs, got %s", expected, string(logLines))
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

	logLines := w.Read()
	expected = "example.com"
	if !strings.Contains(string(logLines), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, string(logLines))
	}
	expected = conn.LocalAddr().String()
	if !strings.Contains(string(logLines), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, string(logLines))
	}
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

func requestHTTP(domain string) ([]byte, net.Conn, error) {
	listener, err := getProxyServer(handleHTTPConnection)
	if err != nil {
		return nil, nil, err
	}

	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		return nil, nil, err
	}
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: "+domain+"\r\nContent-Length: 0\r\n\r\n")
	content, err := ioutil.ReadAll(conn)

	return content, conn, err
}

func requestHTTPS(SNIServerName, requestServerName string) ([]byte, net.Conn, error) {
	listener, err := getProxyServer(handleHTTPSConnection)
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

func getProxyServer(handler func(net.Conn)) (net.Listener, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	go func(handler func(net.Conn)) {
		connection, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		handler(connection)
	}(handler)

	return listener, nil
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
