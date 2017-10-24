package nsspe

import (
	"plugin"
)

type IPlugBase interface {
	ProcessSections(sections []SectionHeader) string
}

func LoadPlugin(path string) (IPlugBase, error) {
	plug, err := plugin.Open(path)
	if err != nil {
		return nil, err
	}

	sym, err := plug.Lookup("ProcessSections")
	if err != nil {
		return nil, err
	}

	var symbols IPlugBase
	symbols = sym.(IPlugBase)

	return symbols, nil
}
