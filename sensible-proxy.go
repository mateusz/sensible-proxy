package main

// sensible-proxy
//
// By default sensible-proxy will listen on port 80 and 443, this can be changed
// by setting the ENV variables PORT and SSLPORT to other values, e.g:
//     $ HTTP_PORT=8080 HTTPS_PORT=8443 sensible-proxy

import (
	"bufio"
	"container/list"
	"crypto/sha1"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

type tcpHandler func(net.Conn, *ConnectionProxy) bool

func main() {
	// don't show any date/times to the console output, as these are shown in the syslog
	// when this program runs as a systemd service
	log.SetFlags(0)

	// default configuration
	var (
		httpPort   = "80"
		httpsPort  = "443"
		appLogPath = "/var/log/sensible-proxy.log"
	)

	// Get configuration from ENV
	if os.Getenv("HTTP_PORT") != "" {
		httpPort = os.Getenv("HTTP_PORT")
	}
	if os.Getenv("HTTPS_PORT") != "" {
		httpsPort = os.Getenv("HTTPS_PORT")
	}
	if os.Getenv("LOG_PATH") != "" {
		appLogPath = os.Getenv("LOG_PATH")
	}

	logFile, err := os.OpenFile(appLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalln("Failed to open log file", err)
	}

	appLog := log.New(io.Writer(logFile), "", 0)

	errChan := make(chan int)

	proxy := &ConnectionProxy{
		port:   httpPort,
		logger: appLog,
	}
	tlsProxy := &ConnectionProxy{
		port:   httpsPort,
		logger: appLog,
	}
	go doProxy(errChan, handleHTTPConnection, proxy)
	go doProxy(errChan, handleHTTPSConnection, tlsProxy)

	// setup capturing of signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

	periodicWhiteListUpdate(proxy, tlsProxy, os.Getenv("WHITELIST_URL"))

	// block until error or signal
	select {
	case <-errChan:
		log.Printf("Stopping server, it crashed.")
		os.Exit(1)
	case <-sigChan:
		log.Printf("Stopping server")
		os.Exit(0)
	}
}

func periodicWhiteListUpdate(proxy, tlsProxy *ConnectionProxy, url string) {
	if url == "" {
		proxy.Logln("No WHITELIST_URL set, allowing all domains")
		return
	}

	ticker := time.NewTicker(time.Second * 60)

	fetch := func() {
		proxy.Logf("Fetching whitelist from '%s'\n", url)
		whiteList := fetchWhiteList(url)
		if len(whiteList) > 0 {
			proxy.Logf("Fetched %d white listed domains\n", len(whiteList))
		} else {
			proxy.Logln("Could not find whitelist, allowing all domains\n")
		}
		proxy.SetWhiteList(whiteList)
		tlsProxy.SetWhiteList(whiteList)
	}

	fetch()
	go func() {
		for range ticker.C {
			fetch()
		}
	}()
}

func doProxy(errChan chan int, handle tcpHandler, proxy *ConnectionProxy) {
	// the proxy should never quit (leaving this function)
	defer func(crash chan int) {
		crash <- 1
	}(errChan)

	listener, err := net.Listen("tcp", "0.0.0.0:"+proxy.port)
	if err != nil {
		log.Printf("Couldn't start listening: %s", err)
		return
	}
	defer proxy.Close(listener)

	log.Printf("Started proxy on %s", proxy.port)
	for {
		connection, err := listener.Accept()
		if err != nil {
			proxy.logger.Println("Accept error:", err)
			continue
		}
		go handle(connection, proxy)
	}
}

func handleHTTPConnection(downstream net.Conn, proxy *ConnectionProxy) bool {
	reader := bufio.NewReader(downstream)
	hostname := ""
	readLines := list.New()
	for hostname == "" {
		bytes, _, err := reader.ReadLine()
		if err != nil {
			return proxy.LogError(fmt.Sprintf("Error during copy between connections: %s", err), hostname, downstream)
		}
		line := string(bytes)
		readLines.PushBack(line)
		if line == "" {
			// End of HTTP headers
			break
		}
		if strings.HasPrefix(line, "Host: ") {
			hostname = strings.TrimPrefix(line, "Host: ")
			break
		}
	}

	if !proxy.IsWhiteListed(hostname) {
		return proxy.LogError(fmt.Sprintf("Hostname is not whitelisted"), hostname, downstream)
	}

	// will timeout with the default linux TCP timeout
	upstream, err := net.Dial("tcp", "www."+hostname+":80")
	if err != nil {
		return proxy.LogError(fmt.Sprintf("Couldn't connect to backend: %s", err), hostname, downstream)
	}

	// proxy the clients request to the upstream
	for element := readLines.Front(); element != nil; element = element.Next() {
		line := element.Value.(string)

		if _, err := upstream.Write([]byte(line)); err != nil {
			return proxy.LogError(fmt.Sprintf("Error while proxying initial request to backend: %s", err), hostname, downstream)
		}

		if _, err = upstream.Write([]byte("\n")); err != nil {
			return proxy.LogError(fmt.Sprintf("Error while proxying initial request to backend: %s", err), hostname, downstream)
		}
	}

	go copyAndClose(upstream, reader, proxy)
	go copyAndClose(downstream, upstream, proxy)

	// by getting here, it seems there are no problems with the connection. Log the successful access.
	return proxy.LogAccess(hostname, downstream)
}

func handleHTTPSConnection(downstream net.Conn, proxy *ConnectionProxy) bool {
	firstByte := make([]byte, 1)
	_, err := downstream.Read(firstByte)
	if err != nil {
		return proxy.LogError("TLS header - couldn't read first byte.", "", downstream)
	}
	if firstByte[0] != 0x16 {
		return proxy.LogError("TLS header - not TLS.", "", downstream)
	}

	versionBytes := make([]byte, 2)
	_, err = downstream.Read(versionBytes)
	if err != nil {
		return proxy.LogError("TLS header - couldn't read version bytes.", "", downstream)
	}
	if versionBytes[0] < 3 || (versionBytes[0] == 3 && versionBytes[1] < 1) {
		return proxy.LogError("TLS header - SSL < 3.1, SNI not supported.", "", downstream)
	}

	restLengthBytes := make([]byte, 2)
	_, err = downstream.Read(restLengthBytes)
	if err != nil {
		return proxy.LogError(fmt.Sprintf("TLS header - couldn't read restLength bytes: %s", err), "", downstream)
	}
	restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

	rest := make([]byte, restLength)

	if n, err := downstream.Read(rest); err != nil || n == 0 {
		return proxy.LogError(fmt.Sprintf("TLS header - couldn't read rest of bytes: %s", err), "", downstream)
	}

	current := 0

	handshakeType := rest[0]
	current++
	if handshakeType != 0x1 {
		return proxy.LogError("TLS header parsing problem - not a ClientHello.", "", downstream)
	}

	// Skip over another length
	current += 3
	// Skip over protocolversion
	current += 2
	// Skip over random number
	current += 4 + 28
	// Skip over session ID
	sessionIDLength := int(rest[current])
	current++
	current += sessionIDLength

	cipherSuiteLength := (int(rest[current]) << 8) + int(rest[current+1])
	current += 2
	current += cipherSuiteLength

	compressionMethodLength := int(rest[current])
	current++
	current += compressionMethodLength

	if current > restLength {
		return proxy.LogError("TLS header parsing problem - no extensions.", "", downstream)
	}

	// Skip over extensionsLength
	// extensionsLength := (int(rest[current]) << 8) + int(rest[current + 1])
	current += 2

	hostname := ""
	for current < restLength && hostname == "" {
		extensionType := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		extensionDataLength := (int(rest[current]) << 8) + int(rest[current+1])
		current += 2

		if extensionType == 0 {

			// Skip over number of names as we're assuming there's just one
			current += 2

			nameType := rest[current]
			current++
			if nameType != 0 {
				return proxy.LogError("TLS header parsing problem - not a hostname.", hostname, downstream)
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			hostname = string(rest[current : current+nameLen])
		}

		current += extensionDataLength
	}

	if hostname == "" || hostname == "127.0.0.1" {
		return proxy.LogError("TLS header parsing problem - no hostname found.", hostname, downstream)
	}

	if !proxy.IsWhiteListed(hostname) {
		return proxy.LogError("Hostname is not whitelisted", hostname, downstream)
	}

	// proxy the clients request to the upstream
	upstream, err := net.Dial("tcp", "www."+hostname+":443")
	if err != nil {
		return proxy.LogError(fmt.Sprintf("Couldn't connect to backend: %s", err), hostname, downstream)
	}

	if _, err = upstream.Write(firstByte); err != nil {
		return proxy.LogError(fmt.Sprintf("Error while proxying first byte to backend: %s", err), hostname, downstream)
	}

	if _, err = upstream.Write(versionBytes); err != nil {
		return proxy.LogError(fmt.Sprintf("Error while proxying versionBytes to backend: %s", err), hostname, downstream)
	}

	if _, err = upstream.Write(restLengthBytes); err != nil {
		return proxy.LogError(fmt.Sprintf("Error while proxying restLengthBytes to backend: %s", err), hostname, downstream)
	}

	if _, err = upstream.Write(rest); err != nil {
		return proxy.LogError(fmt.Sprintf("Error while proxying rest to backend: %s", err), hostname, downstream)
	}

	go copyAndClose(upstream, downstream, proxy)
	go copyAndClose(downstream, upstream, proxy)

	// by getting here, it seems there are no problems with the connection. Log the successful access.
	return proxy.LogAccess(hostname, downstream)
}

func fetchWhiteList(URL string) []string {
	resp, err := http.Get(URL)
	// if there is an error, just allow all
	if err != nil {
		return []string{}
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	// if there is an error, just allow all
	if err != nil {
		return []string{}
	}
	result := []string{}
	lines := strings.Split(string(body), "\n")
	for i := range lines {
		// length of a SHA1 is 40 chars
		if len(lines[i]) == 40 {
			result = append(result, lines[i])
		}
	}
	return result
}

func copyAndClose(dst io.WriteCloser, src io.Reader, proxy *ConnectionProxy) {
	_, err := io.Copy(dst, src)
	if err != nil {
		// this is a bit of hack until the core net lib gives us better
		// typed error. The below error is expected since either the
		// client or backend can close the connection when ever they
		// feel like it.
		str := err.Error()
		if !strings.Contains(str, "use of closed network connection") {
			proxy.LogError(fmt.Sprintf("Error during copy between connections: %s", err), "", nil)
		}
	}
	proxy.Close(dst)
}

// SHA1 returns a string representation of the calculated SHA1 of the input
func SHA1(s string) string {
	h := sha1.New()
	// we are ignore errors here
	h.Write([]byte(s))
	return fmt.Sprintf("%x\n", h.Sum(nil))
}
