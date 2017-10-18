package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"

	"./nsspe"
)

func processfile(filename string, scanType, signaturePath, outpath string) {
	pe := &nsspe.Parsed{}
	pe.Path = filename
	buffer, _ := ioutil.ReadFile(pe.Path)

	fmt.Printf("Parsing %s...\n", filename)
	err := pe.Parse(buffer, scanType, signaturePath)
	if err != nil {
		fmt.Printf("Error processing %v: %v\n", filename, err)
		return
	}
	json, err := json.Marshal(pe)
	if err != nil {
		fmt.Printf("Error JSON encoding %v: %v\n", filename, err)
		return
	}
	ioutil.WriteFile(filepath.Join(outpath, filepath.Base(filename)+".json"), json, 0644)
}

func main() {
	var filename string
	var path string
	var signaturePath string
	var scanType string
	var outPath string
	flag.StringVar(&filename, "file", "", "Process this file")
	flag.StringVar(&path, "path", "C:/Windows/System32", "Path to start scanning files for PE parsing.")
	flag.StringVar(&signaturePath, "signdb", "userdb.txt", "Path to the PEiD signature database.")
	flag.StringVar(&scanType, "signature", "eponly", "no, full or eponly signature scanning enable.")
	flag.StringVar(&outPath, "outpath", "", "Output path for reports.")

	flag.Parse()

	if len(flag.Args()) > 0 {
		for _, name := range flag.Args() {
			processfile(name, scanType, signaturePath, outPath)
		}
	} else if filename != "" {
		// Process a file
		processfile(filename, scanType, signaturePath, outPath)
	} else {
		// Process a folder
		files, err := ioutil.ReadDir(path)
		if err != nil {
			log.Fatal(err)
		}

		for _, f := range files {
			//			fmt.Println("Parsing " + f.Name())
			processfile(filepath.Join(path, f.Name()), scanType, signaturePath, outPath)
		}
	}
	/*	pe := &nsspe.Parsed{}
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
		ioutil.WriteFile("SlaveInject.json", data, 0644) */
}
