package client

import "log"

var cmdListKeyTemplates = &Command{
	Run:       runListKeyTemplates,
	UsageLine: "key-templates",
	Short:     "Lists the supported tink key templates",
	Long: `
	Lists the supported tink key templates.
`,
}

func runListKeyTemplates(_ *Command, _ []string) *ErrorStatus {
	log.Println("The following tink key templates are supported:")
	log.Println(nameOfSupportedTinkKeyTemplates())
	return nil
}
