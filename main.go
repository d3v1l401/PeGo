package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"

	"./nsspe"
)

func main() {

	var path string
	var signaturePath string
	var scanType string
	flag.StringVar(&path, "path", "C:/Windows/System32", "Path to start scanning files for PE parsing.")
	flag.StringVar(&signaturePath, "signdb", "userdb.txt", "Path to the PEiD signature database.")
	flag.StringVar(&scanType, "signature", "eponly", "no, full or eponly signature scanning enable.")

	flag.Parse()
	/*
		files, err := ioutil.ReadDir(path)
		if err != nil {
			log.Fatal(err)
		}

		pe := &nsspe.Parsed{}
		for _, f := range files {
			if strings.Contains(f.Name(), ".exe") || strings.Contains(f.Name(), ".dll") {

				fmt.Println("Parsing " + f.Name())
				pe.Load(path + "/" + f.Name())

				json, _ := json.Marshal(pe)
				ioutil.WriteFile("out\\"+f.Name()+".json", json, 0644)
			}
		}
	*/

	pe := &nsspe.Parsed{}
	pe.Path = "procexp.exe.target"
	// buffer, _ := ioutil.ReadFile("target.exe")
	buffer, _ := ioutil.ReadFile(pe.Path)

	err := pe.Parse(buffer, scanType, signaturePath)
	if err != nil {
		fmt.Printf("Parsing %s produced an error: %s.\n", pe.Path, err.Error())
	} else {
		fmt.Printf("Parsed %s successfully.\n", pe.Path)
	}
	data, _ := json.Marshal(pe)
	ioutil.WriteFile("out32.json", data, 0644)

	pe2 := &nsspe.Parsed{}
	pe2.Path = "procexp64.exe.target"
	buffer, _ = ioutil.ReadFile(pe2.Path)
	err = pe2.Parse(buffer, scanType, signaturePath)
	if err != nil {
		fmt.Printf("Parsing %s produced an error: %s.\n", pe2.Path, err.Error())
	} else {
		fmt.Printf("Parsed %s successfully.\n", pe2.Path)
	}
	data, _ = json.Marshal(pe2)
	ioutil.WriteFile("out64.json", data, 0644)

	pe3 := &nsspe.Parsed{}
	pe3.Path = "SlaveInject.exe"
	buffer, _ = ioutil.ReadFile(pe3.Path)
	err = pe3.Parse(buffer, scanType, signaturePath)
	if err != nil {
		fmt.Printf("Parsing %s produced an error: %s.\n", pe3.Path, err.Error())
	} else {
		fmt.Printf("Parsed %s successfully.\n", pe3.Path)
	}
	data, _ = json.Marshal(pe3)
	ioutil.WriteFile("SlaveInject.json", data, 0644)
}
