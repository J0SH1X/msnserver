package main

import(
	"io/ioutil"
	"fmt"
	"encoding/json"
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