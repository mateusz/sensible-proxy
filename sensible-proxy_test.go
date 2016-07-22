package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"sync"
	"testing"
)

func TestHTTPConnection(t *testing.T) {
	w := &BufferWriter{}

	proxy := getMockProxy(w, "google.com")
	actual, conn, err := requestHTTP("google.com", proxy)
	if err != nil {
		t.Errorf("%s\n", err)
		return
	}
	defer conn.Close()

	// depending on the area you are testing from you might get a 301 or 302
	expected := "HTTP/1.0 30"

	if !strings.Contains(string(actual), expected) {
		t.Errorf("Expected response to contain '%s' got:\n%s", expected, string(actual))
	}

	logLines := w.Content()
	expected = "google.com"
	if !strings.Contains(string(logLines), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, string(logLines))
	}
	expected = conn.LocalAddr().String()
	if !strings.Contains(string(logLines), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, string(logLines))
	}
}

func TestHTTPConnectToNoneExistingDNS(t *testing.T) {
	w := &BufferWriter{}
	proxy := getMockProxy(w)
	content, conn, err := requestHTTP("t.ls", proxy)
	if err != nil {
		t.Errorf("%s\n", err)
		return
	}
	defer conn.Close()

	if string(content) != "" {
		t.Errorf("Expected read to be empty")
	}
	logLines := w.Content()
	expected := "Couldn't connect to backend"
	if !strings.Contains(string(logLines), expected) {
		t.Errorf("Expected '%s' in logs, got %s", expected, string(logLines))
	}
}

func TestHTTPSConnection(t *testing.T) {
	w := &BufferWriter{}
	proxy := getMockProxy(w, "google.com")
	actual, conn, err := requestHTTPS("google.com", "google.com", proxy)
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

	logLines := w.Content()
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
	w := &BufferWriter{}
	proxy := getMockProxy(w, "google.com")

	_, conn, err := requestHTTPS("", "google.com", proxy)
	if conn != nil {
		t.Errorf("Expected connection to be nil")
		conn.Close()
	}

	if err != io.EOF {
		t.Errorf("Expected connection to be closed with an EOF")
	}
	logLines := w.Content()
	expected := "TLS header parsing problem - no hostname found"
	if !strings.Contains(string(logLines), expected) {
		t.Errorf("Expected '%s' in logs, got %s", expected, string(logLines))
	}
}

func TestHTTPSConnectionWrongSNI(t *testing.T) {
	w := &BufferWriter{}
	proxy := getMockProxy(w, "example.com", "google.com")
	actual, conn, err := requestHTTPS("example.com", "google.com", proxy)
	if err != nil {
		t.Errorf("%s\n", err)
		return
	}
	defer conn.Close()

	expected := "HTTP/1.0 404 Not Found"
	if !strings.Contains(string(actual), expected) {
		t.Errorf("Expected response to contain '%s' got:\n%s", expected, actual)
	}

	logLines := w.Content()
	expected = "example.com"
	if !strings.Contains(string(logLines), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, string(logLines))
	}
	expected = conn.LocalAddr().String()
	if !strings.Contains(string(logLines), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, string(logLines))
	}
}

func TestHTTPWhitelistBlocks(t *testing.T) {
	w := &BufferWriter{}
	proxy := getMockProxy(w, "somedomain.com", "someother.com")
	_, conn, err := requestHTTP("google.com", proxy)
	if err == nil {
		defer conn.Close()
	}
	defer conn.Close()

	logLines := w.Content()
	expected := "google.com ERROR: Hostname is not whitelisted"
	if !strings.Contains(string(logLines), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, string(logLines))
	}
}

func TestHTTPSWhitelistBlocks(t *testing.T) {
	w := &BufferWriter{}
	proxy := getMockProxy(w, "somedomain.com", "someother.com")
	_, conn, err := requestHTTPS("google.com", "google.com", proxy)
	if err == nil {
		defer conn.Close()
	}

	logLines := w.Content()
	expected := "google.com ERROR: Hostname is not whitelisted"
	if !strings.Contains(string(logLines), expected) {
		t.Errorf("Expected log to contain '%s' got:\n%s", expected, string(logLines))
	}
}

func TestHTTPSBadInput(t *testing.T) {
	w := &BufferWriter{}
	proxy := getMockProxy(w)

	var crashers = []string{
		"\x1600\x00",
	}

	for _, crashData := range crashers {
		b := &buffer{}
		b.data = []byte(crashData)
		handleHTTPSConnection(b, proxy)
	}
}

func requestHTTP(domain string, proxy *ConnectionProxy) ([]byte, net.Conn, error) {
	listener, err := getProxyServer(handleHTTPConnection, proxy)
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

func requestHTTPS(SNIServerName, requestServerName string, proxy *ConnectionProxy) ([]byte, net.Conn, error) {
	listener, err := getProxyServer(handleHTTPSConnection, proxy)
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

func getProxyServer(handler tcpHandler, proxy *ConnectionProxy) (net.Listener, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return listener, err
	}
	go func(handler tcpHandler, proxy *ConnectionProxy) {
		connection, err := listener.Accept()
		if err != nil {
			panic(err)
		}
		handler(connection, proxy)
	}(handler, proxy)
	return listener, nil
}

func getMockProxy(mockLogger io.Writer, whiteListedDomains ...string) *ConnectionProxy {
	var whiteList []string
	for _, domain := range whiteListedDomains {
		whiteList = append(whiteList, SHA1(domain))
	}
	return &ConnectionProxy{
		logger:    log.New(mockLogger, "", log.Ldate|log.Ltime),
		whitelist: whiteList,
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

type BufferWriter struct {
	sync.Mutex
	logs []byte
	asd  io.ReadWriteCloser
}

func (w *BufferWriter) Write(p []byte) (n int, err error) {
	w.Lock()
	defer w.Unlock()
	w.logs = append(w.logs, p...)
	return len(p), nil
}

func (w *BufferWriter) Content() []byte {
	w.Lock()
	defer w.Unlock()
	temp := make([]byte, len(w.logs))
	copy(temp, w.logs)
	return temp
}
