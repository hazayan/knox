package client

import (
	"fmt"
	"io/ioutil"
	"os"

	"github.com/pinterest/knox"
)

var cmdCreate = &Command{
	Run:       runCreate,
	UsageLine: "create <key_identifier>",
	Short:     "creates a new key",
	Long: `
Create will create a new key in knox with original data set as the primary data. Key data should be sent to stdin.

The original key version id will be print to stdout.

To create a new key, user credentials are required. The default access list will include the creator of this key and a limited set of site reliablity and security engineers.

For more about knox, see https://github.com/pinterest/knox.

See also: knox add, knox get
	`,
}

func runCreate(cmd *Command, args []string) {
	if len(args) != 1 {
		fatalf("create takes exactly one argument. See 'knox help create'")
	}
	fmt.Println("Reading from stdin...")
	keyID := args[0]
	data, err := ioutil.ReadAll(os.Stdin)
	if err != nil {
		fatalf("Problem reading key data: %s", err.Error())
	}
	// TODO(devinlundberg): allow ACL to be entered as input
	acl := knox.ACL{}
	versionID, err := cli.CreateKey(keyID, data, acl)
	if err != nil {
		fatalf("Error adding version: %s", err.Error())
	}
	fmt.Printf("Created key with initial version %d\n", versionID)
}
