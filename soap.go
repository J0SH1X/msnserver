package main

import (
	"encoding/xml"
	"time"
	"net/http"
	"log"
	"strconv"
)

type AuthEnvelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Header  AuthHeader   `xml:"Header"`
}

type AuthHeader struct {
	AuthInfo AuthInfo `xml:"AuthInfo"`
	Security Security `xml:"Security"`
}

type AuthInfo struct {
	HostingApp    string `xml:"HostingApp"`
	BinaryVersion string `xml:"BinaryVersion"`
	UIVersion     string `xml:"UIVersion"`
	Cookies       string `xml:"Cookies"`
	RequestParams string `xml:"RequestParams"`
}

type Security struct {
	UsernameToken UsernameToken `xml:"UsernameToken"`
}

type UsernameToken struct {
	Username string `xml:"Username"`
	Password string `xml:"Password"`
}

// ===== SOAP Fault Response =====

type SOAPEnvelope struct {
	XMLName xml.Name     `xml:"S:Envelope"`
	XmlnsS  string       `xml:"xmlns:S,attr"`
	XmlnsWsse string     `xml:"xmlns:wsse,attr"`
	XmlnsWsu string      `xml:"xmlns:wsu,attr"`
	XmlnsPsf string      `xml:"xmlns:psf,attr"`
	Header  SOAPHeader   `xml:"S:Header"`
	Fault   SOAPFault    `xml:"S:Fault"`
}

type SOAPHeader struct {
	PP PP `xml:"psf:pp"`
}

type PP struct {
	XMLName       xml.Name `xml:"psf:pp"`
	ServerVersion string   `xml:"psf:serverVersion"`
	AuthState     string   `xml:"psf:authstate"`
	ReqStatus     string   `xml:"psf:reqstatus"`
	ServerInfo    ServerInfo `xml:"psf:serverInfo"`
	Cookies       string   `xml:"psf:cookies"`
	Response      string   `xml:"psf:response"`
}

type ServerInfo struct {
	XMLName              xml.Name `xml:"psf:serverInfo"`
	Path                 string   `xml:"Path,attr"`
	RollingUpgradeState  string   `xml:"RollingUpgradeState,attr"`
	LocVersion           string   `xml:"LocVersion,attr"`
	ServerTime           string   `xml:"ServerTime,attr"`
	Value                string   `xml:",chardata"`
}

type SOAPFault struct {
	FaultCode   string `xml:"faultcode"`
	FaultString string `xml:"faultstring"`
}

// ======= Function to Craft XML =======

func SoapAuthFailed() ([]byte, error) {
	serverTime := time.Now().UTC().Format(time.RFC3339)

	envelope := SOAPEnvelope{
		XmlnsS:   "http://schemas.xmlsoap.org/soap/envelope/",
		XmlnsWsse: "http://schemas.xmlsoap.org/ws/2003/06/secext",
		XmlnsWsu:  "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
		XmlnsPsf:  "http://schemas.microsoft.com/Passport/SoapServices/SOAPFault",
		Header: SOAPHeader{
			PP: PP{
				ServerVersion: "1",
				AuthState:     "0x80048800",
				ReqStatus:     "0x80048823",
				ServerInfo: ServerInfo{
					Path:                "Live1",
					RollingUpgradeState: "ExclusiveNew",
					LocVersion:          "0",
					ServerTime:          serverTime,
					Value:               "XYZPPLOGN1A23 2017.09.28.12.44.07",
				},
				Cookies:  "",
				Response: "",
			},
		},
		Fault: SOAPFault{
			FaultCode:   "wsse:FailedAuthentication",
			FaultString: "Authentication Failure",
		},
	}

	return xml.MarshalIndent(envelope, "", "  ")
}




func handlePassPortLogin(w http.ResponseWriter, r *http.Request) {
	var env AuthEnvelope

	// Read and parse the SOAP XML request
	decoder := xml.NewDecoder(r.Body)
	decoder.DefaultSpace = "http://schemas.xmlsoap.org/soap/envelope/"
	err := decoder.Decode(&env)
	if err != nil {
		log.Printf("Failed to parse SOAP XML: %v", err)
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	log.Printf("Parsed Username: %s", env.Header.Security.UsernameToken.Username)
	log.Printf("Parsed Password: %s", env.Header.Security.UsernameToken.Password)

//check for user in DB here and then decide what to do rn we just reject anything with auth failed

	xmlResp, err := SoapAuthFailed()
	if err != nil {
		log.Printf("Failed to generate SOAP response: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	response := append([]byte(xml.Header), xmlResp...)

	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(response)))

	_, err = w.Write(response)
	if err != nil {
		log.Printf("Failed to send SOAP response: %v", err)
		http.Error(w, "Failed to send response", http.StatusInternalServerError)
		return
	}
}
