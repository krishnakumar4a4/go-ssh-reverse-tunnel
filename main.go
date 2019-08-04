package main

import (
	"encoding/hex"
	//"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strings"
	"time"

	//"time"

	"golang.org/x/crypto/ssh"
)

func getPlainTCPConn() net.Conn {
	l, err := net.Listen("tcp", "0.0.0.0:2345")
	if err != nil {
		fmt.Println("Unable to listen, err:", err)
		return nil
		// handle error
	}
	tcpConn, err := l.Accept()
	if err != nil {
		fmt.Println("Unable to accept connection, err:", err)
		return nil
	}
	return tcpConn
}

func main() {
	// tcpConn := getSSHReverseTunnelConnection()
	// tcpConn := getPlainTCPConn()

	key, err := ioutil.ReadFile("/Users/krishnak/.ssh/id_rsa")
	if err != nil {
		log.Fatalf("unable to read private key: %v", err)
		// return nil
	}

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
		// return nil
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
		// return nil
	}
	defer conn.Close()

	// Request the remote side to open port 8080 on all interfaces.
	l, err := conn.Listen("tcp", "0.0.0.0:2345")
	if err != nil {
		log.Fatal("unable to register tcp forward: ", err)
		// return nil
	}
	defer l.Close()

	fmt.Println("read started")
	tcpConn, err := l.Accept()
	if err != nil {
		fmt.Println("error tcp accept: ", err)
		// return nil
	}
	fmt.Println("connection accepted")

	url := parseConnect(tcpConn)
	fmt.Println("url: ", url)

	targetConn, err := net.Dial("tcp", url)
	if err != nil {
		fmt.Println("Unable to connect to target host: ", url)
	}

	//go transfer(targetConn, tcpConn)
	//go transfer(tcpConn, targetConn)
	BUFSIZE := 1024 * 5
	// for {
		go func() {
			for {
			tcpConnBuf := make([]byte, BUFSIZE)
			fmt.Println("reading from ssh conn")
			n, err := tcpConn.Read(tcpConnBuf)
			fmt.Printf("tcpConnBuf: %v, size: %v", hex.EncodeToString(tcpConnBuf[:n]), n)
			if n != 0 {
				fmt.Println("wrote to target conn")
				targetConn.Write(tcpConnBuf[:n])
			}
			// if n < BUFSIZE {
			// 	fmt.Println("ssh read broke")
			// 	break
			// }
			if err != nil {
				if err == io.EOF {
					fmt.Println("reading from ssh conn, EOF")
					break
				}
				fmt.Println("Read all err: ", err)
			}
		}
	}()
		// time.Sleep(time.Second * 1)
		go func() {
			for {
			targetConnBuf := make([]byte, BUFSIZE)
			fmt.Println("reading from target conn")
			n, err := targetConn.Read(targetConnBuf)
			fmt.Printf("targetConnBuf: %v, size: %v", hex.EncodeToString(targetConnBuf[:n]), n)
			if n != 0 {
				fmt.Println("wrote to ssh conn")
				tcpConn.Write(targetConnBuf[:n])
			}
			// if n < BUFSIZE {
			// 	fmt.Println("tcp read broke")
			// 	break
			// }
			if err != nil {
				if err == io.EOF {
					fmt.Println("reading from target conn, EOF")
					break
				}
				fmt.Println("Read all err: ", err)
			}
		}
	}()
	for {
		time.Sleep(time.Second * 1)
	}
		// time.Sleep(time.Second * 1)
	// }
}

func transfer(destination io.WriteCloser, source io.ReadCloser) {
	defer destination.Close()
	defer source.Close()
	for {
		time.Sleep(10 * time.Millisecond)
		io.Copy(destination, source)
	}
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

func getSSHReverseTunnelConnection() (net.Conn) {
	// A public key may be used to authenticate against the remote
	// server by using an unencrypted PEM-encoded private key file.
	//
	// If you have an encrypted private key, the crypto/x509 package
	// can be used to decrypt it.
	key, err := ioutil.ReadFile("/Users/krishnak/.ssh/id_rsa")
	if err != nil {
		log.Fatalf("unable to read private key: %v", err)
		return nil
	}

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.Fatalf("unable to parse private key: %v", err)
		return nil
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
		return nil
	}
	defer conn.Close()

	// Request the remote side to open port 8080 on all interfaces.
	l, err := conn.Listen("tcp", "0.0.0.0:2345")
	if err != nil {
		log.Fatal("unable to register tcp forward: ", err)
		return nil
	}
	defer l.Close()

	fmt.Println("read started")
	tcpConn, err := l.Accept()
	if err != nil {
		fmt.Println("error tcp accept: ", err)
		return nil
	}
	fmt.Println("connection accepted")
	return tcpConn
}

// type serverHelloMsg struct {
// 	raw                          []byte
// 	vers                         uint16
// 	random                       []byte
// 	sessionId                    []byte
// 	cipherSuite                  uint16
// 	compressionMethod            uint8
// 	nextProtoNeg                 bool
// 	nextProtos                   []string
// 	ocspStapling                 bool
// 	scts                         [][]byte
// 	ticketSupported              bool
// 	secureRenegotiation          []byte
// 	secureRenegotiationSupported bool
// 	alpnProtocol                 string
// }

// // TLS extension numbers
// const (
// 	extensionServerName          uint16 = 0
// 	extensionStatusRequest       uint16 = 5
// 	extensionSupportedCurves     uint16 = 10
// 	extensionSupportedPoints     uint16 = 11
// 	extensionSignatureAlgorithms uint16 = 13
// 	extensionALPN                uint16 = 16
// 	extensionSCT                 uint16 = 18 // https://tools.ietf.org/html/rfc6962#section-6
// 	extensionSessionTicket       uint16 = 35
// 	extensionNextProtoNeg        uint16 = 13172 // not IANA assigned
// 	extensionRenegotiationInfo   uint16 = 0xff01
// )

// func (m *serverHelloMsg) unmarshal(data []byte) bool {
// 	if len(data) < 42 {
// 		return false
// 	}
// 	m.raw = data
// 	m.vers = uint16(data[4])<<8 | uint16(data[5])
// 	m.random = data[6:38]
// 	sessionIdLen := int(data[38])
// 	if sessionIdLen > 32 || len(data) < 39+sessionIdLen {
// 		return false
// 	}
// 	m.sessionId = data[39 : 39+sessionIdLen]
// 	data = data[39+sessionIdLen:]
// 	if len(data) < 3 {
// 		return false
// 	}
// 	m.cipherSuite = uint16(data[0])<<8 | uint16(data[1])
// 	m.compressionMethod = data[2]
// 	data = data[3:]

// 	m.nextProtoNeg = false
// 	m.nextProtos = nil
// 	m.ocspStapling = false
// 	m.scts = nil
// 	m.ticketSupported = false
// 	m.alpnProtocol = ""

// 	if len(data) == 0 {
// 		// ServerHello is optionally followed by extension data
// 		return true
// 	}
// 	if len(data) < 2 {
// 		return false
// 	}

// 	extensionsLength := int(data[0])<<8 | int(data[1])
// 	data = data[2:]
// 	if len(data) != extensionsLength {
// 		return false
// 	}

// 	for len(data) != 0 {
// 		if len(data) < 4 {
// 			return false
// 		}
// 		extension := uint16(data[0])<<8 | uint16(data[1])
// 		length := int(data[2])<<8 | int(data[3])
// 		data = data[4:]
// 		if len(data) < length {
// 			return false
// 		}

// 		switch extension {
// 		case extensionNextProtoNeg:
// 			m.nextProtoNeg = true
// 			d := data[:length]
// 			for len(d) > 0 {
// 				l := int(d[0])
// 				d = d[1:]
// 				if l == 0 || l > len(d) {
// 					return false
// 				}
// 				m.nextProtos = append(m.nextProtos, string(d[:l]))
// 				d = d[l:]
// 			}
// 		case extensionStatusRequest:
// 			if length > 0 {
// 				return false
// 			}
// 			m.ocspStapling = true
// 		case extensionSessionTicket:
// 			if length > 0 {
// 				return false
// 			}
// 			m.ticketSupported = true
// 		case extensionRenegotiationInfo:
// 			if length == 0 {
// 				return false
// 			}
// 			d := data[:length]
// 			l := int(d[0])
// 			d = d[1:]
// 			if l != len(d) {
// 				return false
// 			}

// 			m.secureRenegotiation = d
// 			m.secureRenegotiationSupported = true
// 		case extensionALPN:
// 			d := data[:length]
// 			if len(d) < 3 {
// 				return false
// 			}
// 			l := int(d[0])<<8 | int(d[1])
// 			if l != len(d)-2 {
// 				return false
// 			}
// 			d = d[2:]
// 			l = int(d[0])
// 			if l != len(d)-1 {
// 				return false
// 			}
// 			d = d[1:]
// 			if len(d) == 0 {
// 				// ALPN protocols must not be empty.
// 				return false
// 			}
// 			m.alpnProtocol = string(d)
// 		case extensionSCT:
// 			d := data[:length]

// 			if len(d) < 2 {
// 				return false
// 			}
// 			l := int(d[0])<<8 | int(d[1])
// 			d = d[2:]
// 			if len(d) != l || l == 0 {
// 				return false
// 			}

// 			m.scts = make([][]byte, 0, 3)
// 			for len(d) != 0 {
// 				if len(d) < 2 {
// 					return false
// 				}
// 				sctLen := int(d[0])<<8 | int(d[1])
// 				d = d[2:]
// 				if sctLen == 0 || len(d) < sctLen {
// 					return false
// 				}
// 				m.scts = append(m.scts, d[:sctLen])
// 				d = d[sctLen:]
// 			}
// 		}
// 		data = data[length:]
// 	}

// 	return true
// }
