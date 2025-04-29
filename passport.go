package main

import (
	"encoding/xml"
	"time"
	"net/http"
	"log"
	"strconv"
	"gorm.io/gorm"
	"golang.org/x/crypto/bcrypt"
	"fmt"
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
	Fault   SOAPFault    `xml:"S:Fault,omitempty"`
}

type Body struct {
	XML                        string                                  `xml:",innerxml"`
	RequestSecurityTokenResponseCollection RequestSecurityTokenResponseCollection `xml:"wst:RequestSecurityTokenResponseCollection"`
}

type RequestSecurityTokenResponseCollection struct {
	XMLName                          xml.Name	  `xml:"wst:RequestSecurityTokenResponseCollection"`
	XmlnsS  						 string       `xml:"xmlns:S,attr"`
	XmlnsWST  						 string       `xml:"xmlns:wst,attr"`
	XmlnsWSSE  					 string       `xml:"xmlns:wsse,attr"`
	XmlnsWSU  					 string       `xml:"xmlns:wsu,attr"`
	XmlnsSAML  					 string       `xml:"xmlns:saml,attr"`
	XmlnsWSP  					 string       `xml:"xmlns:wsp,attr"`
	XmlnsPSF  					 string       `xml:"xmlns:psf,attr"`                            
	RequestSecurityTokenResponses    []RequestSecurityTokenResponse      `xml:"wst:RequestSecurityTokenResponse"`
}

type RequestSecurityTokenResponse struct {
	XMLName                   xml.Name                 `xml:"wst:RequestSecurityTokenResponse"`
	TokenType                 string                   `xml:"wst:TokenType"`
	AppliesTo                 AppliesTo                `xml:"wsp:AppliesTo"`
	LifeTime                  LifeTime                 `xml:"wst:LifeTime"`
	RequestedSecurityToken    RequestedSecurityToken   `xml:"wst:RequestedSecurityToken"`
	RequestedTokenReference   RequestedTokenReference  `xml:"wst:RequestedTokenReference"`
	RequestedProofToken       RequestedProofToken      `xml:"wst:RequestedProofToken,omitempty"`
}

type AppliesTo struct {
	EndpointReference EndpointReference `xml:"wsa:EndpointReference"`
	XmlnsWSA		  string			`xml:"xmlns:wsa,attr"`
}

type EndpointReference struct {
	Address string `xml:"wsa:Address"`
}

type LifeTime struct {
	Created string `xml:"wsu:Created"`
	Expires string `xml:"wsu:Expires"`
}

type RequestedSecurityToken struct {
	EncryptedData *EncryptedData `xml:"EncryptedData,omitempty"`
	BinarySecurityToken BinarySecurityToken `xml:"wsse:BinarySecurityToken"`
}

type EncryptedData struct {
	XMLName         xml.Name `xml:"EncryptedData,omitempty"`
	XmlNS			string   `xml:"xmlns,attr,omitempty"`
	Id				string   `xml:"Id,attr,omitempty"`
	Type			string   `xml:"Type,attr,omitempty"`
	EncryptionMethod EncryptionMethod `xml:"EncryptionMethod,omitempty"`
	KeyInfo         KeyInfo `xml:"ds:KeyInfo,omitempty"`
	CipherData      CipherData `xml:"CipherData,omitempty"`
}

type EncryptionMethod struct {
	Algorithm string `xml:"Algorithm,attr,omitempty"`
}

type KeyInfo struct {
	KeyName string `xml:"ds:KeyName,omitempty"`
	XmlnsDS	string `xml:"xmlns:ds,attr,omitempty"`
}

type CipherData struct {
	CipherValue string `xml:"CipherValue,omitempty"`
}

type BinarySecurityToken struct {
	ID    string `xml:"Id,attr"`
	Value string `xml:",chardata"`
}

type RequestedTokenReference struct {
	KeyIdentifier KeyIdentifier `xml:"wsse:KeyIdentifier"`
	Reference     Reference     `xml:"wsse:Reference"`
}

type KeyIdentifier struct {
	ValueType string `xml:"ValueType,attr"`
}

type Reference struct {
	URI string `xml:"URI,attr"`
}

type RequestedProofToken struct {
	BinarySecret string `xml:"wst:BinarySecret,omitempty"`
}


type SOAPHeader struct {
	PP PP `xml:"psf:pp"`
}

type BrowserCookie struct {
	Name string `xml:"Name,attr"`
	URL  string `xml:"URL,attr"`
	Data string `xml:",chardata"`
}

type CredProperty struct {
	Name  string `xml:"Name,attr"`
	Value string `xml:",chardata"`
}

type ExtProperty struct {
	Name             string `xml:"Name,attr"`
	Expiry           string `xml:"Expiry,attr,omitempty"`
	Domains          string `xml:"Domains,attr,omitempty"`
	IgnoreRememberMe string `xml:"IgnoreRememberMe,attr,omitempty"`
	Value            string `xml:",chardata"`
}

type PP struct {
	XMLName       xml.Name `xml:"psf:pp,omitempty"`
	ServerVersion string   `xml:"psf:serverVersion,omitempty"`
	PUID          string   `xml:"psf:PUID,omitempty"`
	ConfigVersion string   `xml:"psf:configVersion,omitempty"`
	UIVersion     string   `xml:"psf:uiVersion,omitempty"`
	MobileConfigVersion  string   `xml:"psf:mobileConfigVersion,omitempty"`
	AuthState     string   `xml:"psf:authstate,omitempty"`
	ReqStatus     string   `xml:"psf:reqstatus,omitempty"`
	ServerInfo    ServerInfo `xml:"psf:serverInfo,omitempty"`
	Cookies       string   `xml:"psf:cookies,omitempty"`
	BrowserCookies []BrowserCookie `xml:"psf:browserCookies>psf:browserCookie,omitempty"`
	CredProperties       []CredProperty  `xml:"psf:credProperties>psf:credProperty,omitempty"`
	ExtProperties        []ExtProperty   `xml:"psf:extProperties>psf:extProperty,omitempty"`
	Response	  string `xml:"psf:response"`
	XmlnsPsf      string   `xml:"xmlns:psf,attr,omitempty"`
}

type PP1 struct {
	XMLName       xml.Name `xml:"psf:pp,omitempty"`
	ServerVersion string   `xml:"psf:serverVersion,omitempty"`
	PUID          string   `xml:"psf:PUID,omitempty"`
	ConfigVersion string   `xml:"psf:configVersion,omitempty"`
	UIVersion     string   `xml:"psf:uiVersion,omitempty"`
	MobileConfigVersion  string   `xml:"psf:mobileConfigVersion,omitempty"`
	AuthState     string   `xml:"psf:authstate,omitempty"`
	ReqStatus     string   `xml:"psf:reqstatus,omitempty"`
	ServerInfo    ServerInfo `xml:"psf:serverInfo,omitempty"`
	Cookies       string   `xml:"psf:cookies"`
	BrowserCookies []BrowserCookie `xml:"psf:browserCookies>psf:browserCookie,omitempty"`
	CredProperties       []CredProperty  `xml:"psf:credProperties>psf:credProperty,omitempty"`
	ExtProperties        []ExtProperty   `xml:"psf:extProperties>psf:extProperty,omitempty"`
	Response	  string `xml:"psf:response"`
	XmlnsPsf      string   `xml:"xmlns:psf,attr,omitempty"`
}

type ServerInfo struct {
	XMLName              xml.Name `xml:"psf:serverInfo"`
	Path                 string   `xml:"Path,attr"`
	RollingUpgradeState  string   `xml:"RollingUpgradeState,attr"`
	LocVersion           string   `xml:"LocVersion,attr"`
	ServerTime           string   `xml:"ServerTime,attr"`
	Value                string   `xml:",chardata"`
	Content            string `xml:",chardata"`
}

type SOAPFault struct {
	FaultCode   string `xml:"faultcode,omitempty"`
	FaultString string `xml:"faultstring,omitempty"`
}

// ======= Function to Craft XML =======

func PassPortAuthFailed(errorCode string) ([]byte, error) {
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
				ReqStatus:     errorCode,
				ServerInfo: ServerInfo{
					Path:                "Live1",
					RollingUpgradeState: "ExclusiveNew",
					LocVersion:          "0",
					ServerTime:          serverTime,
					Value:               "XYZPPLOGN1A23 2017.09.28.12.44.07",
				},
				Cookies:  "",
			},
		},
		Fault: SOAPFault{
			FaultCode:   "wsse:FailedAuthentication",
			FaultString: "Authentication Failure",
		},
	}

	return xml.MarshalIndent(envelope, "", "  ")
}

func PassPortAuthSuccess(user *User) ([]byte, error){
	//toDO find out how to generate a session token for passport.net and craft a valid resp

	now := time.Now().UTC().Format(time.RFC3339)
	expires := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)

	type PPSOAPHeader struct {
		PP PP1 `xml:"psf:pp"`
	}

	type PassPortEnvelope struct {
		XMLName xml.Name     `xml:"S:Envelope"`
		XmlnsS  string       `xml:"xmlns:S,attr"`
		Header  PPSOAPHeader   `xml:"S:Header"`
		Body    Body     	 `xml:"S:Body"`
	}



	envelope := PassPortEnvelope{
		XmlnsS: "http://schemas.xmlsoap.org/soap/envelope/",
		Header: PPSOAPHeader{
			PP: PP1{
				XmlnsPsf:             "http://schemas.microsoft.com/Passport/SoapServices/SOAPFault",
				ServerVersion:        "1",
				PUID:                 "EF115ED63AE25535",
				ConfigVersion:        "16.000.26889.00",
				UIVersion:            "3.100.2179.0",
				MobileConfigVersion:  "16.000.26208.0",
				AuthState:            "0x48803",
				ReqStatus:            "0x0",
				ServerInfo: ServerInfo{
					Path:               "Live1",
					RollingUpgradeState: "ExclusiveNew",
					LocVersion:         "0",
					ServerTime:         now,
					Content:            "XYZPPLOGN1A23 2017.10.03.19.00.04",
				},
				Cookies: "",
				BrowserCookies: []BrowserCookie{
					{Name: "MH", URL: "http://www.msn.com", Data: "MSFT; path=/; domain=.msn.com; expires=Wed, 30-Dec-2037 16:00:00 GMT"},
					{Name: "MHW", URL: "http://www.msn.com", Data: "; path=/; domain=.msn.com; expires=Thu, 30-Oct-1980 16:00:00 GMT"},
					{Name: "MH", URL: "http://www.live.com", Data: "MSFT; path=/; domain=.live.com; expires=Wed, 30-Dec-2037 16:00:00 GMT"},
					{Name: "MHW", URL: "http://www.live.com", Data: "; path=/; domain=.live.com; expires=Thu, 30-Oct-1980 16:00:00 GMT"},
				},
				CredProperties: []CredProperty{
					{Name: "MainBrandID", Value: "MSFT"},
					{Name: "BrandIDList", Value: ""},
					{Name: "IsWinLiveUser", Value: "true"},
					{Name: "CID", Value: "8aa0f85a3ae25535"},
					{Name: "AuthMembername", Value: user.Email},
					{Name: "Country", Value: "US"},
					{Name: "Language", Value: "1033"},
					{Name: "FirstName", Value: "John"},
					{Name: "LastName", Value: "Doe"},
					{Name: "ChildFlags", Value:"00000001"},
					{Name: "Flags", Value: "40100643"},
					{Name: "FlagsV2", Value: "00000000"},
					{Name: "IP", Value: "127.0.0.1"},
					{Name: "FamilyID", Value: "0000000000000000"},
					{Name: "AssociatedForStrongAuth", Value: "0"},
				},
				ExtProperties: []ExtProperty{
					{Name: "ANON", Expiry: "Wed, 30-Dec-2037 16:00:00 GMT", Domains: "bing.com;atdmt.com", IgnoreRememberMe: "false", Value: "A=2AD1B6380CC38C61A2E95994FFFFFFFF&amp;E=1456&amp;W=1"},
					{Name: "NAP", Expiry: "Wed, 30-Dec-2037 16:00:00 GMT", Domains: "bing.com;atdmt.com", IgnoreRememberMe: "false", Value: "V=1.9&amp;E=13fc&amp;C=tq1sGI5NyECr4nbob0bsqOGQx85gOAzYs8FuhJP5L22WfJl-67MNNQ&amp;W=1"},
					{Name: "LastUsedCredType", Value: "1"},
					{Name: "WebCredType", Value: "1"},
					{Name: "CID", Value: "8aa0f85a3ae25535"},
				},
			},
		},
		Body: Body{
			RequestSecurityTokenResponseCollection: RequestSecurityTokenResponseCollection{
				XmlnsS: "http://schemas.xmlsoap.org/soap/envelope/",
				XmlnsWST: "http://schemas.xmlsoap.org/ws/2004/04/trust",
				XmlnsWSSE: "http://schemas.xmlsoap.org/ws/2003/06/secext",
				XmlnsWSU: "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
				XmlnsSAML: "urn:oasis:names:tc:SAML:1.0:assertion",
				XmlnsWSP: "http://schemas.xmlsoap.org/ws/2002/12/policy",
				XmlnsPSF: "http://schemas.microsoft.com/Passport/SoapServices/SOAPFault",
				RequestSecurityTokenResponses: []RequestSecurityTokenResponse{
					{
						TokenType: "urn:passport:legacy",
						AppliesTo: AppliesTo{
							XmlnsWSA: "http://schemas.xmlsoap.org/ws/2004/03/addressing",
							EndpointReference: EndpointReference{
								Address: "http://Passport.NET/tb",
							},
						},
						LifeTime: LifeTime{
							Created: now,
							Expires: expires,
						},
						RequestedSecurityToken: RequestedSecurityToken{
							EncryptedData: &EncryptedData{
								XmlNS: "http://www.w3.org/2001/04/xmlenc#",
								Id: "BinaryDAToken0",
								Type: "http://www.w3.org/2001/04/xmlenc#Element",
								EncryptionMethod: EncryptionMethod{
									Algorithm: "http://www.w3.org/2001/04/xmlenc#tripledes-cbc",
								},
								KeyInfo: KeyInfo{
									KeyName: "http://Passport.NET/STS",
									XmlnsDS: "http://www.w3.org/2000/09/xmldsig#",
								},
								CipherData: CipherData{
									CipherValue: "Cap26AQZrSyMm2SwwTyJKyqLR9...",
								},
							},
						},
						RequestedTokenReference: RequestedTokenReference{
							KeyIdentifier: KeyIdentifier{
								ValueType: "urn:passport",
							},
							Reference: Reference{
								URI: "#BinaryDAToken0",
							},
						},
						RequestedProofToken: RequestedProofToken{
							BinarySecret: "tgoPVK67sU36fQKlGLMgWgTXp7oiaQgE",
						},
					},
					{
						TokenType: "urn:passport:compact",
						AppliesTo: AppliesTo{
							XmlnsWSA: "http://schemas.xmlsoap.org/ws/2004/03/addressing",
							EndpointReference: EndpointReference{
								Address: "messenger.msn.com",
							},
						},
						LifeTime: LifeTime{
							Created: now,
							Expires: expires,
						},
						RequestedSecurityToken: RequestedSecurityToken{
							EncryptedData: nil,
							BinarySecurityToken: BinarySecurityToken{
								ID: "Compact2",
								Value: user.SessionToken,
							},
						},
						RequestedTokenReference: RequestedTokenReference{
							KeyIdentifier: KeyIdentifier{
								ValueType: "urn:passport:compact",
							},
							Reference: Reference{
								URI: "#Compact2",
							},
						},
					},
				},
			},
		},
		
	}

	return xml.MarshalIndent(envelope, "", "\t")
}


func handlePassPortLogin(db *gorm.DB, w http.ResponseWriter, r *http.Request) {
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

	var user User
	var xmlResp []byte
	if err := db.First(&user, "email = ?",  env.Header.Security.UsernameToken.Username).Error; err != nil {
		log.Println("failed to retrieve user:", err)
		xmlResp, err = PassPortAuthFailed("0x80048823")
	} else {
		err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(env.Header.Security.UsernameToken.Password))
		if err != nil {
			// Password doesn't match
			log.Println("pass Wrong")
			xmlResp, err = PassPortAuthFailed("0x80048823")
		} else {
			log.Println("pass correct")
			salt := []byte("1234567890ABCDEFGHIJKLNM")
			decryptedToken := fmt.Sprintf("%s+%s+%s", user.Username, user.Password, time.Now().UTC().Format(time.RFC3339))
			user.SessionToken, err = generateCipherValue(decryptedToken, salt)
			err = saveSessionToken(user.ID,user.SessionToken,db)
			if (err != nil){
				log.Println("cannot generate Sessiontoken: ", err)
				xmlResp, err = PassPortAuthFailed("0x99999999")
			}else {
			xmlResp, err = PassPortAuthSuccess(&user)
				  }
		}
	}

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
