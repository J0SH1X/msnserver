package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"strings"
	"bytes"
	"encoding/xml"
	"encoding/json"
	"io/ioutil"
	"strconv"
)

var GlobalConfig Config

func handleMSNPConnection(conn net.Conn) {
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
			if len(parts) >= 5 && parts[2] == "TWN" && parts[3] == "I" {
				email := parts[4]
				fakeToken := "ct=1234567890,rn=fakeredirect"
				fmt.Fprintf(conn, "USR %s TWN S %s\r\n", trID, fakeToken)
				log.Printf("MSNP: Sent fake Passport challenge for %s", email)
			}

		default:
			log.Printf("MSNP: Unhandled command: %s", cmd)
		}
	}
}

func handleSOAPRequest(data []byte) {
	var env Envelope
	decoder := xml.NewDecoder(bytes.NewReader(data))
	decoder.DefaultSpace = "http://schemas.xmlsoap.org/soap/envelope/"
	err := decoder.Decode(&env)
	if err != nil {
		log.Printf("Failed to parse SOAP XML: %v", err)
		return
	}

	log.Printf("Parsed Username: %s", env.Header.Security.UsernameToken.Username)
	log.Printf("Parsed Password: %s", env.Header.Security.UsernameToken.Password)
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
		go handleMSNPConnection(conn)
	}
}

func listenSSL(port string, certFile, keyFile string) {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		log.Fatalf("SSL: Error loading SSL certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		//tls1.2
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS12,
	}

	tlsListener, err := tls.Listen("tcp", port, tlsConfig)
	if err != nil {
		log.Fatalf("SSL: Error starting SSL listener on %s: %v", port, err)
	}
	log.Printf("SSL: MSN server running on SSL port %s...", port)

	for {
		conn, err := tlsListener.Accept()
		if err != nil {
			log.Println("SSL: SSL Connection error:", err)
			continue
		}

		go func() {
			buf := make([]byte, 1024)
			for {
				n, err := conn.Read(buf)
				if err != nil {
					log.Println("SSL: Error reading from SSL connection:", err)
					return
				}
				log.Printf("SSL: SSL - Received %d bytes: %s", n, string(buf[:n]))
				handleSOAPRequest(buf[:n])
			}
		}()
	}
}


func loadConfig(filename string) (Config, error) {
	var config Config

	// Read the file content
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return config, fmt.Errorf("could not read config file: %v", err)
	}

	// Unmarshal the JSON data into the Config struct
	err = json.Unmarshal(data, &config)
	if err != nil {
		return config, fmt.Errorf("could not parse config: %v", err)
	}

	return config, nil
}



func main() {


	config, err := loadConfig("config.json")
	if err != nil {
		log.Fatalf("%v", err)
	}
	GlobalConfig = config

	go listenTCP(":" + strconv.Itoa(config.Server.Msnpport))

	certFile := config.Server.Certpath
	keyFile := config.Server.Keypath
	go listenSSL(":" + strconv.Itoa(config.Server.Sslport), certFile, keyFile)

	select {}
}
