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
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"io"
	"bytes"
)


type ShieldsXML struct{
	XMLName xml.Name `xml:"config"`
	Shield Shield `xml:"shield"`
	Block string `xml:"block"`
}

type Shield struct{
	Cli Cli `xml:"cli"`
}

type Cli struct{
	Maj string `xml:"maj,attr"`
	Min string `xml:"min,attr"`
	Minbld string `xml:"minbld,attr"`
	Maxbld string `xml:"maxbld,attr"`
	Deny   string `xml:"deny,attr"`
}

var GlobalConfig Config


func generateCipherValue(plaintext string, key []byte) (string, error) {
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return "", err
	}

	iv := make([]byte, des.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	padding := des.BlockSize - len(plaintext)%des.BlockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	padded := append([]byte(plaintext), padtext...)

	ciphertext := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, padded)

	final := append(iv, ciphertext...)

	cipherValue := base64.StdEncoding.EncodeToString(final)

	return cipherValue, nil
}

func getMD5Hash(text string) string {
	hash := md5.Sum([]byte(text))
	return hex.EncodeToString(hash[:])
 }

func handleMSNPRequest(conn net.Conn, db *gorm.DB) {
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
			userSessionToken := parts[4]
			if len(parts) >= 5 && parts[2] == "TWN" && parts[3] == "I" {
				fakeToken := "ct=1,rver=1,wp=FS40SEC_0_COMPACT,lc=1,id=1"
				fmt.Fprintf(conn, "USR %s TWN S %s\r\n", trID, fakeToken)
				log.Printf("MSNP: Received USR command, responding with: USR %s TWN S %s\r\n", trID, fakeToken)
			}
			if len(parts) >= 5 && parts[2] == "TWN" && parts[3] == "S" {
				var user User
				if err := db.First(&user, "session_token = ?",  userSessionToken).Error; err != nil {
					log.Println("failed to retrieve user:", err)
					//idk what to do here tbh probably close the connection
					conn.Close()
				} else {
					//save current ip for later use
					clientAddr := conn.RemoteAddr().String()
					clientIpParts := strings.Split(clientAddr, ":")
					if db.Model(&User{}).Where("id = ?", user.ID).Update("ip", clientIpParts[0]).Error != nil {
						log.Println("Error updating ClientIP for userID: ", user.ID)
					}
					log.Println("https challange passed")
					fmt.Fprintf(conn, "USR %s OK %s 1 0 \r\n", trID,user.Email)
					fmt.Fprintf(conn, "SBS 0 null\r\n")
					body := fmt.Sprintf(
						"MIME-Version: 1.0\r\n"+
						"Content-Type: text/x-msmsgsprofile; charset=UTF-8\r\n"+
						"LoginTime: 1745610395\r\n"+
						"EmailEnabled: 0\r\n"+
						"MemberIdHigh: %d\r\n"+
						"MemberIdLow: %d\r\n"+
						"lang_preference: 1033\r\n"+
						"preferredEmail:\r\n"+
						"country:\r\n"+
						"PostalCode:\r\n"+
						"Gender:\r\n"+
						"Kid: 0\r\n"+
						"Age:\r\n"+
						"BDayPre:\r\n"+
						"Birthday:\r\n"+
						"Wallet:\r\n"+
						"Flags: 536872513\r\n"+
						"sid: 507\r\n"+
						"MSPAuth: %s\r\n"+
						"ClientIP: %s\r\n"+
						"ClientPort: %s\r\n"+
						"ABCHMigrated: 1\r\n"+
						"MPOPEnabled: 0\r\n"+
						"BetaInvites: 1\r\n"+
						"\r\n",
						user.ID, user.ID, userSessionToken, clientIpParts[0], clientIpParts[1],
					)
					
					header := fmt.Sprintf("MSG Hotmail Hotmail %d\r\n", len(body))
					
					fullMessage := []byte(header + body)
					
					_, err := conn.Write(fullMessage)
					if err != nil {
						log.Println("Error writing MSG to connection:", err)
					}
					
				}
			}

		case "SYN":
			//probly syncs time we just send back what we got here
			fmt.Fprintf(conn, "SYN %s %s %s 0 0 \r\n" ,trID, "2000-01-01T00:00:00.0-00:00", "2000-01-01T00:00:00.0-00:00")
			log.Println("Received SYN command, responding with: SYN" ,trID, "2000-01-01T00:00:00.0-00:00", "2000-01-01T00:00:00.0-00:00", "0 0 \r\n")
			fmt.Fprintf(conn, "GTC A \r\n")
		case "GCF":
			//time.Sleep(2 * time.Second) 
			shieldsXML := ShieldsXML{
				Shield: Shield{
					Cli: Cli{
						Maj:    "7",
						Min:    "0",
						Minbld: "0",
						Maxbld: "9999",
						Deny:   "audio camera phone",
					},
				},
				Block: "",
			}
			xmlBytes, err := xml.MarshalIndent(shieldsXML, "", "\t")
			if err != nil {
				log.Println("Error marshaling XML:", err)
				return
			}
		
			// Include XML header if needed by client
			xmlData := append([]byte(xml.Header), xmlBytes...)
		
			// MSNP12 requires: GCF <trid> Shields.xml <length>\r\n<xml>
			header := fmt.Sprintf("GCF %s Shields.xml %d\r\n", trID, len(xmlData))
		
			fullMessage := append([]byte(header), xmlData...)
		
			_, err = conn.Write(fullMessage)
			if err != nil {
				log.Println("Error sending XML over TCP:", err)
			}

			log.Println("Received GCF shields.xml, responding with: ",fullMessage)
		case "PNG":
			fmt.Fprintf(conn,"QNG 60")

		case "OUT":
			//delete session token from DB
			log.Println("user logout")
			conn.Close()
		default:
			log.Printf("MSNP: Unhandled command: %s", cmd)
		}
	}
}

func listenTCP(db *gorm.DB,port string) {
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
		go handleMSNPRequest(conn,db)
	}
}

func listenSSL(db *gorm.DB, port, certFile, keyFile string) {
	http.HandleFunc("/RST.srf", func(w http.ResponseWriter, r *http.Request) {
		handlePassPortLogin(db, w, r)
	})
	http.HandleFunc("/useradd", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			http.ServeFile(w, r, "html/newuser.html")
		} else if r.Method == http.MethodPost {
			addUser(db, w, r)
		} else {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		}
	})

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

	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",GlobalConfig.DB.User, GlobalConfig.DB.Password, GlobalConfig.DB.Host, GlobalConfig.DB.Port, GlobalConfig.DB.Database)
	db, err1 := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err1 != nil {
		log.Fatal("failed to connect to the database:", err)
	}

	if (config.DB.DoAutoMigrate){
		db.AutoMigrate(&User{})
	}

	go listenTCP(db,":" + strconv.Itoa(config.Server.Msnpport))
	go listenSSL(db,":" + strconv.Itoa(config.Server.Sslport), config.Server.Certpath, config.Server.Keypath)

	select {}
}
