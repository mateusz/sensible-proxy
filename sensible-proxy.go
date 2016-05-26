package main

// sensible-proxy
//
// By default sensible-proxy will listen on port 80 and 443, this can be changed
// by setting the ENV variables PORT and SSLPORT to other values, e.g:
//     $ HTTP_PORT=8080 HTTPS_PORT=8443 sensible-proxy

import (
	"bufio"
	"container/list"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

var appLog *log.Logger

func main() {
	log.SetFlags(0)
	// default configuration
	var (
		httpPort   string = "80"
		httpsPort  string = "443"
		appLogPath string = "/var/log/sensible-proxy.log"
	)

	// Get configuration from ENV
	if envVarSet("HTTP_PORT") {
		httpPort = os.Getenv("HTTP_PORT")
	}
	if envVarSet("HTTPS_PORT") {
		httpsPort = os.Getenv("HTTPS_PORT")
	}
	if envVarSet("LOG_PATH") {
		appLogPath = os.Getenv("LOG_PATH")
	}

	logFile, err := os.OpenFile(appLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.Fatalln("Failed to open log file", err)
	}
	appLog = log.New(io.Writer(logFile), "", log.Ldate|log.Ltime)

	errChan := make(chan int)
	go doProxy(errChan, httpPort, handleHTTPConnection)
	go doProxy(errChan, httpsPort, handleHTTPSConnection)

	// setup capturing of signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGHUP,
		syscall.SIGINT,
		syscall.SIGTERM,
		syscall.SIGQUIT)

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

func copyAndClose(dst io.WriteCloser, src io.Reader) {
	_, err := io.Copy(dst, src)
	if err != nil {
		appLog.Println("Error during copy between connections: :", err)
	}
	close(dst)
}

func handleHTTPConnection(downstream net.Conn) {
	reader := bufio.NewReader(downstream)
	hostname := ""
	readLines := list.New()
	for hostname == "" {
		bytes, _, error := reader.ReadLine()
		if error != nil {
			close(downstream)
			appLog.Println("Error reading from connection:", error)
			return
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

	// log the access
	appLog.Println(downstream.RemoteAddr().String(), hostname)

	// will timeout with the default linux TCP timeout
	upstream, err := net.Dial("tcp", "www."+hostname+":80")
	if err != nil {
		close(downstream)
		appLog.Println("Couldn't connect to backend:", err)
		return
	}

	// proxy the clients request to the upstream
	for element := readLines.Front(); element != nil; element = element.Next() {
		line := element.Value.(string)
		_, err := upstream.Write([]byte(line))
		if err != nil {
			appLog.Println("Error while proxying initial request to backend: %s", err)
		}
		_, err = upstream.Write([]byte("\n"))
		if err != nil {
			appLog.Println("Error while proxying initial request to backend: %s", err)
		}
	}

	go copyAndClose(upstream, reader)
	go copyAndClose(downstream, upstream)
}

func close(c io.Closer) {
	err := c.Close()
	if err != nil {
		appLog.Println("Error when closing connection: %s", err)
	}
}

func handleHTTPSConnection(downstream net.Conn) {
	firstByte := make([]byte, 1)
	_, err := downstream.Read(firstByte)
	if err != nil {
		close(downstream)
		appLog.Println("TLS header parsing problem - couldn't read first byte.")
		return
	}
	if firstByte[0] != 0x16 {
		close(downstream)
		appLog.Println("TLS header parsing problem - not TLS.")
		return
	}

	versionBytes := make([]byte, 2)
	_, err = downstream.Read(versionBytes)
	if err != nil {
		close(downstream)
		appLog.Println("TLS header parsing problem - couldn't read version bytes.")
		return
	}
	if versionBytes[0] < 3 || (versionBytes[0] == 3 && versionBytes[1] < 1) {
		close(downstream)
		appLog.Println("TLS header parsing problem - SSL < 3.1, SNI not supported.")
		return
	}

	restLengthBytes := make([]byte, 2)
	_, err = downstream.Read(restLengthBytes)
	if err != nil {
		close(downstream)
		appLog.Println("TLS header parsing problem - couldn't read restLength bytes:", err)
		return
	}
	restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

	rest := make([]byte, restLength)
	n, err := downstream.Read(rest)
	if err != nil || n == 0 {
		close(downstream)
		appLog.Println("TLS header parsing problem - couldn't read rest of bytes:", err)
		return
	}

	current := 0

	handshakeType := rest[0]
	current += 1
	if handshakeType != 0x1 {
		close(downstream)
		appLog.Println("TLS header parsing problem - not a ClientHello.")
		return
	}

	// Skip over another length
	current += 3
	// Skip over protocolversion
	current += 2
	// Skip over random number
	current += 4 + 28
	// Skip over session ID
	sessionIDLength := int(rest[current])
	current += 1
	current += sessionIDLength

	cipherSuiteLength := (int(rest[current]) << 8) + int(rest[current+1])
	current += 2
	current += cipherSuiteLength

	compressionMethodLength := int(rest[current])
	current += 1
	current += compressionMethodLength

	if current > restLength {
		close(downstream)
		appLog.Println("TLS header parsing problem - no extensions.")
		return
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
			current += 1
			if nameType != 0 {
				appLog.Println("TLS header parsing problem - not a hostname.")
				return
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			hostname = string(rest[current : current+nameLen])
		}

		current += extensionDataLength
	}
	if hostname == "" {
		appLog.Println("TLS header parsing problem - no hostname found.")
		return
	}

	// log the access
	appLog.Println(downstream.RemoteAddr().String(), hostname)

	// proxy the clients request to the upstream
	upstream, err := net.Dial("tcp", "www."+hostname+":443")
	if err != nil {
		appLog.Println("Couldn't connect to backend:", err)
		close(downstream)
		return
	}

	_, err = upstream.Write(firstByte)
	if err != nil {
		appLog.Println("Error while proxying first byte to backend: %s", err)
	}
	_, err = upstream.Write(versionBytes)
	if err != nil {
		appLog.Println("Error while proxying versionBytes to backend: %s", err)
	}
	_, err = upstream.Write(restLengthBytes)
	if err != nil {
		appLog.Println("Error while proxying restLengthBytes to backend: %s", err)
	}
	_, err = upstream.Write(rest)
	if err != nil {
		appLog.Println("Error while proxying rest to backend: %s", err)
	}

	go copyAndClose(upstream, downstream)
	go copyAndClose(downstream, upstream)
}

func reportError(errChan chan int) {
	errChan <- 1
}

func doProxy(errChan chan int, port string, handle func(net.Conn)) {
	defer reportError(errChan)

	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		log.Printf("Couldn't start listening: %s", err)
		return
	}
	defer close(listener)

	log.Printf("Started proxy on %s", port)
	for {
		connection, err := listener.Accept()
		if err != nil {
			appLog.Println("Accept error:", err)
			continue
		}
		go handle(connection)
	}
}

func envVarSet(name string) bool {
	if os.Getenv(name) != "" {
		return true
	}
	return false
}
