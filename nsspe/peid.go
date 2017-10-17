package nsspe

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"regexp"
	"strings"
)

const (
	MAX_RECOMMENDED_SEARCH_SCANS = iota
	RECOMMENDED_DEEPNESS         = 3
)

const (
	STRING_REGEXP_QUERY = "\\[(.*?)\\]\\s+?signature\\s*=\\s*(.*?)(\\s+\\?\\?)*\\s*ep_only\\s*=\\s*(\\w+)(?:\\s*section_start_only\\s*=\\s*(\\w+)|)"
)

type SignatureEntry struct {
	Name           string
	Signature      string
	EntryPointOnly bool
}

type SignatureDatabase struct {
	Entries []SignatureEntry
}

func (s *SignatureDatabase) ExportAsJSON(path string) error {
	buff, err := json.Marshal(s)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(path, buff, 0644)
	if err != nil {
		return err
	}

	return nil
}

func (s *SignatureDatabase) getByte(data string) byte {
	if len(data) == 2 {
		decode, err := hex.DecodeString(data)
		if err != nil {
			fmt.Println("Warning: byte decode for ", data, " failed.")
			return 0x00
		}

		return decode[0]
	}
	return 0x00
}

func (s *SignatureDatabase) isWildCard(data string) bool {
	if len(data) == 2 {
		if strings.Compare("??", data) == 0 {
			return true
		}
	}
	return false
}

func (s *SignatureDatabase) compare(data byte, sigByte string) bool {
	if s.isWildCard(sigByte) {
		return true
	}

	hexed, err := hex.DecodeString(sigByte)
	if err != nil {
		return false
	}
	if data == hexed[0] {
		return true
	}

	return false
}

func (s *SignatureDatabase) scan(buffer []byte, mask string) uint {
	var countValid int = 0
	tokens := strings.Split(mask, " ")

	for index := 0; index < len(buffer); index++ {
		if s.compare(buffer[index], tokens[countValid]) {
			countValid++

			if countValid == len(tokens) {
				return uint(countValid)
			}
		} else {
			countValid = 0
		}
	}

	return 0
}

func (s *SignatureDatabase) MatchAll(buffer []byte, deepness int, maxTrials int) []int {
	var matches []int
	var deep int
	var trials int

	if maxTrials == MAX_RECOMMENDED_SEARCH_SCANS {
		maxTrials = len(s.Entries) / 3
	} else if maxTrials == 0 {
		maxTrials = len(s.Entries)
	}

	for id, sign := range s.Entries {
		trials++
		if (s.scan(buffer, sign.Signature)) != 0 {
			matches = append(matches, id)
			deep++
			if deep == deepness {
				break
			}
		}
		if trials == maxTrials {
			break
		}
	}

	return matches
}

func LoadJSONSignatures(path string) (*SignatureDatabase, error) {
	var db SignatureDatabase
	buff, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	err = json.Unmarshal(buff, &db)
	if err != nil {
		return nil, err
	}

	return &db, nil
}

func (s *SignatureDatabase) parseEntry(entry []byte) error {
	if len(entry) > 6 {
		splitted := strings.Split(string(entry), "\n")
		if len(splitted) == 3 {
			var entry SignatureEntry
			entry.Name = string(splitted[0][1 : len(splitted[0])-2])
			entry.Signature = splitted[1][len("signature = ") : len(splitted[1])-1]
			if strings.Compare(splitted[2], "ep_only = true") == 0 {
				entry.EntryPointOnly = true
			} else {
				entry.EntryPointOnly = false
			}

			s.Entries = append(s.Entries, entry)
			return nil
		} else {
			return errors.New("Signature does not present 3 fields")
		}
	}
	return errors.New("Signature too small!")
}

func LoadSignatures(path string) (*SignatureDatabase, error) {

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	regexped := regexp.MustCompile(STRING_REGEXP_QUERY)

	var db SignatureDatabase
	var lastPtr int = 0

	for {
		found := regexped.Find(data[lastPtr:len(data)])
		if found != nil {
			lastPtr += len(found)
		} else {
			break
		}
		if err := db.parseEntry(found); err != nil {
			return nil, err
		}
	}

	return &db, nil
}
