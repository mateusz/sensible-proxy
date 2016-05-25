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
	"strconv"
	"strings"
	"syscall"
)

func main() {
	// default configuration
	var (
		httpPort  int = 80
		httpsPort int = 443
	)

	// Remove the default prefixing for log output, rely on process
	// supervisor to prefix the timestamp and process name
	log.SetFlags(0)

	// Get configuration from ENV
	var err error
	if envVarSet("HTTP_PORT") {
		httpPort, err = intFromEnvVar("HTTP_PORT")
		if err != nil {
			log.Printf("Could not convert ENV variable HTTP_PORT to an integer")
		}
	}
	if envVarSet("HTTPS_PORT") {
		httpsPort, err = intFromEnvVar("HTTPS_PORT")
		if err != nil {
			log.Printf("Could not convert ENV variable HTTPS_PORT to an integer")
		}
	}
	if err != nil {
		os.Exit(1)
	}

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
		os.Exit(1)
	case <-sigChan:
		os.Exit(0)
	}
}

func copyAndClose(dst io.WriteCloser, src io.Reader) {
	io.Copy(dst, src)
	dst.Close()
}

func handleHTTPConnection(downstream net.Conn) {
	reader := bufio.NewReader(downstream)
	hostname := ""
	readLines := list.New()
	for hostname == "" {
		bytes, _, error := reader.ReadLine()
		if error != nil {
			downstream.Close()
			log.Println("Error reading from connection:", error)
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
		downstream.Close()
		log.Println("Couldn't connect to backend:", err)
		return
	}

	// proxy the clients request to the upstream
	for element := readLines.Front(); element != nil; element = element.Next() {
		line := element.Value.(string)
		upstream.Write([]byte(line))
		upstream.Write([]byte("\n"))
	}

	go copyAndClose(upstream, reader)
	go copyAndClose(downstream, upstream)
}

func handleHTTPSConnection(downstream net.Conn) {
	firstByte := make([]byte, 1)
	_, error := downstream.Read(firstByte)
	if error != nil {
		downstream.Close()
		log.Println("TLS header parsing problem - couldn't read first byte.")
		return
	}
	if firstByte[0] != 0x16 {
		downstream.Close()
		log.Println("TLS header parsing problem - not TLS.")
		return
	}

	versionBytes := make([]byte, 2)
	_, error = downstream.Read(versionBytes)
	if error != nil {
		downstream.Close()
		log.Println("TLS header parsing problem - couldn't read version bytes.")
		return
	}
	if versionBytes[0] < 3 || (versionBytes[0] == 3 && versionBytes[1] < 1) {
		downstream.Close()
		log.Println("TLS header parsing problem - SSL < 3.1, SNI not supported.")
		return
	}

	restLengthBytes := make([]byte, 2)
	_, error = downstream.Read(restLengthBytes)
	if error != nil {
		downstream.Close()
		log.Println("TLS header parsing problem - couldn't read restLength bytes:", error)
		return
	}
	restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

	rest := make([]byte, restLength)
	_, error = downstream.Read(rest)
	if error != nil {
		downstream.Close()
		log.Println("TLS header parsing problem - couldn't read rest of bytes:", error)
		return
	}

	current := 0

	handshakeType := rest[0]
	current += 1
	if handshakeType != 0x1 {
		downstream.Close()
		log.Println("TLS header parsing problem - not a ClientHello.")
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
		downstream.Close()
		log.Println("TLS header parsing problem - no extensions.")
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
				log.Println("TLS header parsing problem - not a hostname.")
				return
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			hostname = string(rest[current : current+nameLen])
		}

		current += extensionDataLength
	}
	if hostname == "" {
		log.Println("TLS header parsing problem - no hostname found.")
		return
	}

	// proxy the clients request to the upstream
	upstream, error := net.Dial("tcp", "www."+hostname+":443")
	if error != nil {
		log.Println("Couldn't connect to backend:", error)
		downstream.Close()
		return
	}

	upstream.Write(firstByte)
	upstream.Write(versionBytes)
	upstream.Write(restLengthBytes)
	upstream.Write(rest)

	go copyAndClose(upstream, downstream)
	go copyAndClose(downstream, upstream)
}

func reportError(errChan chan int) {
	errChan <- 1
}

func doProxy(errChan chan int, port int, handle func(net.Conn)) {
	defer reportError(errChan)

	listener, err := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(port))
	if err != nil {
		log.Println("Couldn't start listening:", err)
		return
	}
	defer listener.Close()

	log.Println("Started proxy on", port, "-- listening...")
	for {
		connection, error := listener.Accept()
		if error != nil {
			log.Println("Accept error:", error)
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

func intFromEnvVar(name string) (int, error) {
	envVar := os.Getenv(name)
	return strconv.Atoi(envVar)
}
