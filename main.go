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
	flag.StringVar(&path, "path", "C:/Windows/System32", "Path to start scanning files for PE parsing.")
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
	fmt.Println(pe.Parse(buffer))
	data, _ := json.Marshal(pe)
	ioutil.WriteFile("out32.json", data, 0644)

	pe2 := &nsspe.Parsed{}
	pe2.Path = "procexp64.exe.target"
	buffer, _ = ioutil.ReadFile(pe2.Path)
	fmt.Println(pe2.Parse(buffer))
	data, _ = json.Marshal(pe2)
	ioutil.WriteFile("out64.json", data, 0644)

}
