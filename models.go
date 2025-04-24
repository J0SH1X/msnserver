package main

import (
	"encoding/xml"
)

type ServerConfig struct {
	Certpath  string `json:"certpath"`
	Keypath   string `json:"keypath"`
	Hostname  string `json:"hostname"`
	Debug     bool   `json:"debug"`
	SSL       bool   `json:"ssl"`
	Msnpport  int    `json:"msnpport"`
	Sslport   int    `json:"sslport"`
}

type Config struct {
	Server ServerConfig `json:"server"`
}

type Envelope struct {
	XMLName xml.Name `xml:"Envelope"`
	Header  Header   `xml:"Header"`
}

type Header struct {
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

