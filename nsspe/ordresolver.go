package nsspe

import (
	"encoding/json"
	"io/ioutil"
	"strconv"
)

type lib map[int]string

func LoadResolveMaps(path string) (map[string]lib, error) {
	var Mapped map[string]lib

	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &Mapped)
	if err != nil {
		return nil, err
	}

	return Mapped, nil
}

func (p *Parsed) resolveOrdinal(ordinal int, library string) string {
	if p.ordMap != nil && len(p.ordMap) > 0 {
		lib := p.ordMap[library]
		return lib[ordinal]
	}

	return strconv.Itoa(ordinal)
}
