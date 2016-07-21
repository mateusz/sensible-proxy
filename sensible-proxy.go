package main

// sensible-proxy
//
// By default sensible-proxy will listen on port 80 and 443, this can be changed
// by setting the ENV variables PORT and SSLPORT to other values, e.g:
//     $ HTTP_PORT=8080 HTTPS_PORT=8443 sensible-proxy

import (
	"bufio"
	"container/list"
	"fmt"
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
	// don't show any date/times to the console output, as these are shown in the syslog
	// when this program runs as a systemd service
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
	appLog = log.New(io.Writer(logFile), "", 0)

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

func logError(data *LogData) {
	data.messageType = "ERROR"
	appLog.Printf("%s\n", data)
}

func logAccess(data *LogData) {
	data.messageType = "ACCESS"
	appLog.Printf("%s\n", data)
}

func copyAndClose(dst io.WriteCloser, src io.Reader) {
	_, err := io.Copy(dst, src)
	if err != nil {
		// this is a bit of hack until the core net lib gives us better
		// typed error. The below error is expected since either the
		// client or backend can close the connection when ever they
		// feel like it.
		str := err.Error()
		if !strings.Contains(str, "use of closed network connection") {
			logError(&LogData{message: fmt.Sprintf("Error during copy between connections: %s", err)})
		}
	}
	close(dst)
}

func handleHTTPConnection(downstream net.Conn) {
	reader := bufio.NewReader(downstream)
	hostname := ""
	readLines := list.New()
	for hostname == "" {
		bytes, _, err := reader.ReadLine()
		if err != nil {
			close(downstream)
			logError(&LogData{
				message:  fmt.Sprintf("Error during copy between connections: %s", err),
				conn:     downstream,
				hostname: hostname,
			})
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

	// will timeout with the default linux TCP timeout
	upstream, err := net.Dial("tcp", "www."+hostname+":80")
	if err != nil {
		logError(&LogData{
			message:  fmt.Sprintf("Couldn't connect to backend: %s", err),
			conn:     downstream,
			hostname: hostname,
		})
		close(downstream)
		return
	}

	// proxy the clients request to the upstream
	for element := readLines.Front(); element != nil; element = element.Next() {
		line := element.Value.(string)
		_, err := upstream.Write([]byte(line))
		if err != nil {
			logError(&LogData{
				message:  fmt.Sprintf("Error while proxying initial request to backend: %s", err),
				conn:     downstream,
				hostname: hostname,
			})
		}
		_, err = upstream.Write([]byte("\n"))
		if err != nil {
			logError(&LogData{
				message:  fmt.Sprintf("Error while proxying initial request to backend: %s", err),
				conn:     downstream,
				hostname: hostname,
			})
		}
	}

	// by getting here, it seems there are no problems with the connection. Log the successful access.
	logAccess(&LogData{conn: downstream, hostname: hostname})

	go copyAndClose(upstream, reader)
	go copyAndClose(downstream, upstream)
}

func close(c io.Closer) {
	err := c.Close()
	if err != nil {
		logError(&LogData{message: fmt.Sprintf("Error when closing connection: %s", err)})
	}
}

func handleHTTPSConnection(downstream net.Conn) {
	firstByte := make([]byte, 1)
	_, err := downstream.Read(firstByte)
	if err != nil {
		logError(&LogData{message: "TLS header parsing problem - couldn't read first byte.", conn: downstream})
		close(downstream)
		return
	}
	if firstByte[0] != 0x16 {
		logError(&LogData{message: "TLS header parsing problem - not TLS.", conn: downstream})
		close(downstream)
		return
	}

	versionBytes := make([]byte, 2)
	_, err = downstream.Read(versionBytes)
	if err != nil {
		logError(&LogData{message: "TLS header parsing problem - couldn't read version bytes.", conn: downstream})
		close(downstream)
		return
	}
	if versionBytes[0] < 3 || (versionBytes[0] == 3 && versionBytes[1] < 1) {
		logError(&LogData{message: "TLS header parsing problem - SSL < 3.1, SNI not supported.", conn: downstream})
		close(downstream)
		return
	}

	restLengthBytes := make([]byte, 2)
	_, err = downstream.Read(restLengthBytes)
	if err != nil {
		logError(&LogData{
			message: fmt.Sprintf("TLS header parsing problem - couldn't read restLength bytes: %s", err),
			conn:    downstream,
		})
		close(downstream)
		return
	}
	restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

	rest := make([]byte, restLength)
	n, err := downstream.Read(rest)
	if err != nil || n == 0 {
		logError(&LogData{
			message: fmt.Sprintf("TLS header parsing problem - couldn't read rest of bytes: %s", err),
			conn:    downstream,
		})
		close(downstream)
		return
	}

	current := 0

	handshakeType := rest[0]
	current += 1
	if handshakeType != 0x1 {
		logError(&LogData{message: "TLS header parsing problem - not a ClientHello.", conn: downstream})
		close(downstream)
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
		logError(&LogData{message: "TLS header parsing problem - no extensions.", conn: downstream})
		close(downstream)
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
				logError(&LogData{
					message:  "TLS header parsing problem - not a hostname.",
					conn:     downstream,
					hostname: hostname,
				})
				return
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			hostname = string(rest[current : current+nameLen])
		}

		current += extensionDataLength
	}
	if hostname == "" {
		logError(&LogData{message: "TLS header parsing problem - no hostname found.", conn: downstream})
		close(downstream)
		return
	}

	// proxy the clients request to the upstream
	upstream, err := net.Dial("tcp", "www."+hostname+":443")
	if err != nil {
		logError(&LogData{
			message:  fmt.Sprintf("Couldn't connect to backend: %s", err),
			conn:     downstream,
			hostname: hostname,
		})
		close(downstream)
		return
	}

	_, err = upstream.Write(firstByte)
	if err != nil {
		logError(&LogData{
			message:  fmt.Sprintf("Error while proxying first byte to backend: %s", err),
			conn:     downstream,
			hostname: hostname,
		})
	}
	_, err = upstream.Write(versionBytes)
	if err != nil {
		logError(&LogData{
			message:  fmt.Sprintf("Error while proxying versionBytes to backend: %s", err),
			conn:     downstream,
			hostname: hostname,
		})
	}
	_, err = upstream.Write(restLengthBytes)
	if err != nil {
		logError(&LogData{
			message:  fmt.Sprintf("Error while proxying restLengthBytes to backend: %s", err),
			conn:     downstream,
			hostname: hostname,
		})
	}
	_, err = upstream.Write(rest)
	if err != nil {
		logError(&LogData{
			message:  fmt.Sprintf("Error while proxying rest to backend: %s", err),
			conn:     downstream,
			hostname: hostname,
		})
	}

	// by getting here, it seems there are no problems with the connection. Log the successful access.
	logAccess(&LogData{conn: downstream, hostname: hostname})

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
