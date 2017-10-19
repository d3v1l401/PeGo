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

func processfile(filename string, scanType, signaturePath, outpath, ordmap string) {
	pe := &nsspe.Parsed{}
	pe.Path = filename
	buffer, _ := ioutil.ReadFile(pe.Path)

	fmt.Printf("Parsing %s...\n", filename)
	pe.OrdinalResolver(ordmap)
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
	var ordMap string
	flag.StringVar(&filename, "file", "procexp64.exe.target", "Process this file.")
	flag.StringVar(&path, "path", "", "Path to start scanning files for PE parsing.")
	flag.StringVar(&signaturePath, "signdb", "userdb.txt", "Path to the PEiD signature database.")
	flag.StringVar(&scanType, "signature", "eponly", "no, full or eponly signature scanning enable.")
	flag.StringVar(&outPath, "outpath", "", "Output path for reports.")
	flag.StringVar(&ordMap, "ordmap", "", "If ordinal mapping is present, specify path.")

	flag.Parse()

	if len(flag.Args()) > 0 {
		for _, name := range flag.Args() {
			processfile(name, scanType, signaturePath, outPath, ordMap)
		}
	} else if filename != "" {
		// Process a file
		processfile(filename, scanType, signaturePath, outPath, ordMap)
	} else {
		// Process a folder
		files, err := ioutil.ReadDir(path)
		if err != nil {
			log.Fatal(err)
		}

		for _, f := range files {
			//			fmt.Println("Parsing " + f.Name())
			processfile(filepath.Join(path, f.Name()), scanType, signaturePath, outPath, ordMap)
		}
	}
}
