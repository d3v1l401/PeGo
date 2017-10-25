package nsspe

import (
	"strconv"
	"strings"
)

func init() {
	AddPlugin(GolangID)
}

var containers = map[int]string{
	4:   "Unknown Go Section (4)",
	18:  "Imports Section",
	30:  "Unknown Go Section (30)",
	43:  "Unknown Go Section (43)",
	57:  "Interoperability Section",
	73:  "Object Type Metadata Section",
	89:  "Uknown Go Section (89)",
	104: "Debug Symbols",
	123: "Symbols Definitions",
}

func GolangID(pe *PE) []Result {
	NumberedSections := 0
	HadErrorConversion := false
	ResultingArray := ""
	if len(pe.Sections) > 0 {
		for _, s := range pe.Sections {
			if strings.HasPrefix(s.Name, "/") {
				num, err := strconv.Atoi(s.Name[1:len(s.Name)])
				if err != nil {
					HadErrorConversion = true
				}

				if num > 0 && num < 200 {
					NumberedSections++
					ResultingArray += containers[num] + ";"
				}
			}
		}

		if HadErrorConversion {
			ResultingArray += "Maybe"
		} else {
			if len(ResultingArray) > 0 {
				ResultingArray += "Yes"
			} else {
				ResultingArray += "No"
			}
		}

		return nil // TO FIX
	}
	return nil // TO FIX
}
