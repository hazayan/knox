package client

import (
	"fmt"
	"io/ioutil"
	"os"
)

var cmdAdd = &Command{
	Run:       runAdd,
	UsageLine: "add <key_identifier>",
	Short:     "adds a new key version to knox",
	Long: `
add adds a new key version to an existing key in knox. Key data should be sent to stdin.

This key version will be set to active upon creation. The version id will be sent to stdout on creation.

This command uses user access and requires write access in the key's ACL.

For more about knox, see https://github.com/pinterest/knox.

See also: knox create, knox promote
	`,
}

func runAdd(cmd *Command, args []string) {
	if len(args) != 1 {
		fatalf("add takes only one argument. See 'knox help add'")
	}
	fmt.Println("Reading from stdin...")
	keyID := args[0]
	data, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fatalf("Problem reading key data: %s", err.Error())
	}
	versionID, err := cli.AddVersion(keyID, data)
	if err != nil {
		fatalf("Error adding version: %s", err.Error())
	}
	fmt.Printf("Added key version %d\n", versionID)
}
