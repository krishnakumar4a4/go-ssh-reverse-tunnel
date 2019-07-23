package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

func main() {
	// A public key may be used to authenticate against the remote
	// server by using an unencrypted PEM-encoded private key file.
	//
	// If you have an encrypted private key, the crypto/x509 package
	// can be used to decrypt it.
	key, err := ioutil.ReadFile("/Users/krishnak/.ssh/id_rsa")
	if err != nil {
		log.Fatalf("unable to read private key: %v", err)
	}

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
	}

	config := &ssh.ClientConfig{
		User: "krishnak",
		Auth: []ssh.AuthMethod{
			// Use the PublicKeys method for remote authentication.
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	// Dial your ssh server.
	conn, err := ssh.Dial("tcp", "localhost:22", config)
	if err != nil {
		log.Fatal("unable to connect: ", err)
	}
	defer conn.Close()

	// Request the remote side to open port 8080 on all interfaces.
	l, err := conn.Listen("tcp", "0.0.0.0:2345")
	if err != nil {
		log.Fatal("unable to register tcp forward: ", err)
	}
	defer l.Close()

	fmt.Println("read started")
	tcpConn, err := l.Accept()
	if err != nil {
		fmt.Println("error tcp accept: ", err)
	}
	fmt.Println("connection accepted")
	// var buf = [100]byte{}
	// tcpConn.Read(&buf)
	// for {
	// 	buf := make([]byte, 100)
	// 	n, err := tcpConn.Read(buf)
	// 	if err != nil {
	// 		fmt.Println("Read all err: ", err)
	// 	}
	// 	fmt.Println("data read: ", string(buf[:n]))
	// }

	url := parseConnect(tcpConn)
	fmt.Println("url: ", url)

	targetConn, err := net.Dial("tcp", url)
	if err != nil {
		fmt.Println("Unable to connect to target host: ", url)
	}

	go transfer(targetConn, tcpConn)
	// BUFSIZE := 1024
	// for {
	// 	for {
	// 		tcpConnBuf := make([]byte, BUFSIZE)
	// 		fmt.Println("reading from ssh conn")
	// 		n, err := tcpConn.Read(tcpConnBuf)
	// 		fmt.Printf("tcpConnBuf: %v, size: %v", hex.EncodeToString(tcpConnBuf[:n]), n)
	// 		if n != 0 {
	// 			fmt.Println("wrote to target conn")
	// 			targetConn.Write(tcpConnBuf[:n])
	// 		}
	// 		if n < BUFSIZE {
	// 			break
	// 		}
	// 		if err != nil {
	// 			if err == io.EOF {
	// 				fmt.Println("reading from ssh conn, EOF")
	// 				break
	// 			}
	// 			fmt.Println("Read all err: ", err)
	// 		}
	// 	}
	// 	time.Sleep(time.Second * 1)
	// 	for {
	// 		targetConnBuf := make([]byte, BUFSIZE)
	// 		fmt.Println("reading from target conn")
	// 		n, err := targetConn.Read(targetConnBuf)
	// 		fmt.Printf("targetConnBuf: %v, size: %v", hex.EncodeToString(targetConnBuf[:n]), n)
	// 		if n != 0 {
	// 			fmt.Println("wrote to ssh conn")
	// 			tcpConn.Write(targetConnBuf[:n])
	// 		}
	// 		if n < BUFSIZE {
	// 			break
	// 		}
	// 		if err != nil {
	// 			if err == io.EOF {
	// 				fmt.Println("reading from target conn, EOF")
	// 				break
	// 			}
	// 			fmt.Println("Read all err: ", err)
	// 		}
	// 	}
	// 	time.Sleep(time.Second * 1)
	// }


	// tcpSignal := make(chan int)
	// Serve HTTP with your SSH server acting as a reverse proxy.
	// http.Serve(l, http.HandlerFunc(func(resp http.ResponseWriter, req *http.Request) {
	// 	fmt.Println("Got request ", req, req.URL.Host)
	// 	resp.WriteHeader(http.StatusOK)
	// 	return
	// }))

	// fmt.Println("post http serve")
	// go func(signal chan int) {
	// 	fmt.Println("spinned off go routine")
	// 	select {
	// 	case <-signal:
	// 		fmt.Println("read started")
	// 		tcpConn, err := l.Accept()
	// 		if err != nil {
	// 			fmt.Println("error tcp accept: ", err)
	// 		}
	// 		// var buf = [100]byte{}
	// 		// tcpConn.Read(&buf)
	// 		data, err := ioutil.ReadAll(tcpConn)
	// 		if err != nil {
	// 			fmt.Println("Read all err: ", err)
	// 		}
	// 		fmt.Println("data read: ", data)
	// 	}
	// 	fmt.Println("go routine done")
	// }(tcpSignal)

	for {
	}
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	io.Copy(destination, source)
}

func resetCRLF(cr1, cr2, lf1, lf2 *bool) {
	*cr1 = false
	*cr2 = false
	*lf1 = false
	*lf2 = false
}

func parseConnect(tcpConn io.ReadWriter) string {
	cr1 := false
	cr2 := false
	lf1 := false
	lf2 := false
	BUFSIZE := 100
	totReqBytes := []byte{}

	for {
		buf := make([]byte, BUFSIZE)
		n, err := tcpConn.Read(buf)
		if err != nil {
			fmt.Println("Read all err: ", err)
		}
		if n < BUFSIZE {
			totReqBytes = append(totReqBytes, buf[:n]...)
			break
		}
		totReqBytes = append(totReqBytes, buf[:n]...)
		// fmt.Println("data read: ", string(buf[:n]))
		for _, b := range buf[:n] {
			if lf2 && b == 10 {
				resetCRLF(&cr1, &cr2, &lf1, &lf2)
				break
			} else if lf2 {
				resetCRLF(&cr1, &cr2, &lf1, &lf2)
			}
			if cr2 && b == 13 {
				lf2 = true
				continue
			} else if cr2 {
				resetCRLF(&cr1, &cr2, &lf1, &lf2)
			}
			if lf1 && b == 10 {
				cr2 = true
				continue
			} else if lf1 {
				resetCRLF(&cr1, &cr2, &lf1, &lf2)
			}
			if !cr1 && b == 13 {
				lf1 = true
				cr1 = true
				continue
			}
		}
	}
	fmt.Println("conn request: ", string(totReqBytes))
	tcpConn.Write(append([]byte("HTTP/1.1 200 Connection established"), []byte{10, 13, 10, 13}...))
	totReqString := string(totReqBytes)
	lines := strings.Split(totReqString, "\n")
	urls := strings.Split(lines[0], " ")
	return urls[1]
}
