package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func init() {
	debugLog = true
}

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
	content, conn, err := requestHTTP("example.invalid", proxy)
	if err != nil {
		t.Errorf("%s\n", err)
		return
	}
	defer conn.Close()

	if string(content) != "" {
		t.Errorf("Expected read to be empty, got '%s'", string(content))
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
	expected := "google.com DEBUG: Hostname is not whitelisted"
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
	expected := "google.com DEBUG: Hostname is not whitelisted"
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

func TestFetchWhiteList(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "baea954b95731c68ae6e45bd1e252eb4560cdc45\n93195596cc1951e7857b5cc80a9e9f01b3b43a7c")
	}))
	defer ts.Close()

	whitelist := fetchWhiteList(ts.URL)
	if len(whitelist) != 2 {
		t.Errorf("Whitelist should have 2 entries")
	}
}

func TestFetchWhiteListEmptyResponse(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "")
	}))
	defer ts.Close()

	whitelist := fetchWhiteList(ts.URL)
	if len(whitelist) != 0 {
		t.Errorf("Whitelist should have 0 entries")
	}
}

func TestFetchWhiteListOnlySHA1(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `baea954b95731c68ae6e45bd1e252eb4560cdc45
not-40char
93195596cc1951e7857b5cc80a9e9f01b3b43a7c
93195596cc1951e7857b5cc80a9e9f01b3b43a7ctNotA40SHA1Either
`)
	}))
	defer ts.Close()

	whitelist := fetchWhiteList(ts.URL)
	if len(whitelist) != 2 {
		t.Errorf("Whitelist should have 2 entries")
	}
}

func TestFetchWhiteListOnlyOneEntry(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "baea954b95731c68ae6e45bd1e252eb4560cdc45")
	}))
	defer ts.Close()

	whitelist := fetchWhiteList(ts.URL)
	if len(whitelist) != 1 {
		t.Errorf("Whitelist should have 1 entry")
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
