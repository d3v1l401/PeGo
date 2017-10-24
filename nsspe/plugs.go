package nsspe

type Result struct {
	Whatever string
}

type PlugInFunc func(*PE) []Result

var plugins []PlugInFunc

func AddPlugin(f PlugInFunc) {
	plugins = append(plugins, f)
}
