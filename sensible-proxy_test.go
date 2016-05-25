package main

import (
	"crypto/tls"
	"fmt"
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
	done := make(chan bool)
	listener, err := getProxyServer(done, handleHTTPConnection)
	conn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}

	actual, err := requestDomainHTTP(conn, "google.com")
	if err != nil {
		t.Errorf("Error on connect: %s", err)
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

	defer conn.Close()
	done <- true
}

func TestHTTPSConnection(t *testing.T) {
	w := &FakeWriter{}
	appLog = log.New(w, "", log.Ldate|log.Ltime)
	done := make(chan bool)
	listener, err := getProxyServer(done, handleHTTPSConnection)
	if err != nil {
		t.Fatal(err)
	}

	conn, err := tls.Dial("tcp", listener.Addr().String(), &tls.Config{
		ServerName: "google.com",
	})
	if err != nil {
		t.Fatal("failed to connect: " + err.Error())
	}

	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: google.com\r\nContent-Length: 0\r\n\r\n")
	actual, err := ioutil.ReadAll(conn)
	if err != nil {
		t.Errorf("Error on read: %s", err)
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

	defer conn.Close()
	done <- true
}

func requestDomainHTTP(conn net.Conn, domain string) ([]byte, error) {
	fmt.Fprintf(conn, "GET / HTTP/1.0\r\nHost: "+domain+"\r\nContent-Length: 0\r\n\r\n")
	return ioutil.ReadAll(conn)
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
