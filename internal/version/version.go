package version

// Build values are overridden by release linker flags after supply-chain gates pass.
var (
	Version = "0.1.0-dev"
	Commit  = "unknown"
)

// Info is the machine-readable identity returned by every command.
type Info struct {
	Component       string `json:"component"`
	Version         string `json:"version"`
	Commit          string `json:"commit"`
	SpecVersion     string `json:"specVersion"`
	ProductionReady bool   `json:"productionReady"`
}

// Current returns immutable build identity without claiming unsigned readiness.
func Current(component string) Info {
	return Info{
		Component:       component,
		Version:         Version,
		Commit:          Commit,
		SpecVersion:     "2.0.0",
		ProductionReady: false,
	}
}
