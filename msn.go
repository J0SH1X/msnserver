package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"strconv"
)

var GlobalConfig Config

func handleMSNPRequest(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)

	log.Printf("MSNP: New connection from %s", conn.RemoteAddr())

	for {
		line, err := reader.ReadString('\r')
		if err != nil {
			log.Println("Connection closed.")
			return
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		log.Printf("MSNP: << %s", line)

		parts := strings.Split(line, " ")
		if len(parts) < 2 {
			continue
		}

		cmd := parts[0]
		trID := parts[1]

		switch cmd {
		case "VER":
			//check if client supports MSNP12 else abort connection
			log.Printf("MSNP: Received VER command, responding with: VER %s MSNP12", trID)
			fmt.Fprintf(conn, "VER %s MSNP12\r\n", trID)

		case "CVR":
			//cut out msn client version from incoming CSR and reply with %version %version %version ssldomain ssldomain
			msnVersion := parts[7]
			response := fmt.Sprintf("CVR %s %s %s %s https://%s https://%s", trID, msnVersion, msnVersion, msnVersion, GlobalConfig.Server.Hostname, GlobalConfig.Server.Hostname )
			log.Printf("MSNP: Received CVR command, responding with: %s", response)
			fmt.Fprintf(conn, "%s\r\n", response)
		

		case "USR":
			//USR 48 TWN S ct=1,rver=1,wp=FS_40SEC_0_COMPACT,lc=1,id=1\r\n
			if len(parts) >= 5 && parts[2] == "TWN" && parts[3] == "I" {
				fakeToken := "ct=1,rver=1,wp=FS40SEC_0_COMPACT,lc=1,id=1"
				fmt.Fprintf(conn, "USR %s TWN S %s\r\n", trID, fakeToken)
				log.Printf("MSNP: Received USR command, responding with: USR %s TWN S %s\r\n", trID, fakeToken)
			}
		
		case "PNG":
			fmt.Fprintf(conn,"QNG 60")

		default:
			log.Printf("MSNP: Unhandled command: %s", cmd)
		}
	}
}

func listenTCP(port string) {
	ln, err := net.Listen("tcp", port)
	if err != nil {
		log.Fatalf("Error starting server on %s: %v", port, err)
	}
	log.Printf("MSNP: MSN server running on port %s...", port)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("Connection error:", err)
			continue
		}
		go handleMSNPRequest(conn)
	}
}

func listenSSL(port, certFile, keyFile string) {
	http.HandleFunc("/RST.srf", handlePassPortLogin)

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	}

	server := &http.Server{
		Addr:      port,
		Handler:   nil,
		TLSConfig: tlsConfig,
	}

	log.Printf("SSL: MSN server running on port %s with TLS 1.2...", port)
	err := server.ListenAndServeTLS(certFile, keyFile)
	if err != nil {
		log.Fatalf("SSL: Error starting HTTPS server: %v", err)
	}
}

func main() {


	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("%v", err)
	}
	GlobalConfig = config

	go listenTCP(":" + strconv.Itoa(config.Server.Msnpport))
	go listenSSL(":" + strconv.Itoa(config.Server.Sslport), config.Server.Certpath, config.Server.Keypath)

	select {}
}
