package main

import (
	"bufio"
	"container/list"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

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
			fmt.Println("Error reading", error)
			downstream.Close()
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

	upstream, error := net.Dial("tcp", "www."+hostname+":80")
	if error != nil {
		fmt.Println("Couldn't connect to backend", error)
		downstream.Close()
		return
	}

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
		fmt.Println("Couldn't read first byte :-(")
		return
	}
	if firstByte[0] != 0x16 {
		fmt.Println("Not TLS :-(")
	}

	versionBytes := make([]byte, 2)
	_, error = downstream.Read(versionBytes)
	if error != nil {
		fmt.Println("Couldn't read version bytes :-(")
		return
	}
	if versionBytes[0] < 3 || (versionBytes[0] == 3 && versionBytes[1] < 1) {
		fmt.Println("SSL < 3.1 so it's still not TLS")
		return
	}

	restLengthBytes := make([]byte, 2)
	_, error = downstream.Read(restLengthBytes)
	if error != nil {
		fmt.Println("Couldn't read restLength bytes :-(")
		return
	}
	restLength := (int(restLengthBytes[0]) << 8) + int(restLengthBytes[1])

	rest := make([]byte, restLength)
	_, error = downstream.Read(rest)
	if error != nil {
		fmt.Println("Couldn't read rest of bytes")
		return
	}

	current := 0

	handshakeType := rest[0]
	current += 1
	if handshakeType != 0x1 {
		fmt.Println("Not a ClientHello")
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
		fmt.Println("no extensions")
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
				fmt.Println("Not a hostname")
				return
			}
			nameLen := (int(rest[current]) << 8) + int(rest[current+1])
			current += 2
			hostname = string(rest[current : current+nameLen])
		}

		current += extensionDataLength
	}
	if hostname == "" {
		fmt.Println("No hostname")
		return
	}

	upstream, error := net.Dial("tcp", "www."+hostname+":443")
	if error != nil {
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

func reportDone(done chan int) {
	done <- 1
}

func doProxy(done chan int, port int, handle func(net.Conn)) {
	defer reportDone(done)

	listener, error := net.Listen("tcp", "0.0.0.0:"+strconv.Itoa(port))
	if error != nil {
		fmt.Println("Couldn't start listening", error)
		return
	}
	fmt.Println("Started proxy on", port, "-- listening...")
	for {
		connection, error := listener.Accept()
		if error != nil {
			fmt.Println("Accept error", error)
			return
		}

		go handle(connection)
	}
}

func main() {
	httpDone := make(chan int)
	go doProxy(httpDone, 80, handleHTTPConnection)

	httpsDone := make(chan int)
	go doProxy(httpsDone, 443, handleHTTPSConnection)

	<-httpDone
	<-httpsDone
}
