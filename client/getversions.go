package client

import (
	"fmt"
	"strings"

	"github.com/pinterest/knox"
)

func init() {
	cmdGetVersions.Run = runGetVersions // break init cycle
}

var cmdGetVersions = &Command{
	UsageLine: "versions [-s state] <key_identifier>",
	Short:     "gets the versions for a key",
	Long: `
versions get all of the version ids for a key.

-s specifies the minimum state of key to return. By default this is set to active which means active and primary keys are returned. Accepted values include inactive, active, and primary.

This requires read access to the key and can use user or machine authentication.

For more about knox, see https://github.com/pinterest/knox.

See also: knox keys, knox get
	`,
}
var getVersionsState = cmdGetVersions.Flag.String("s", "active", "")

func runGetVersions(cmd *Command, args []string) {
	if len(args) != 1 {
		fatalf("get takes only one argument. See 'knox help versions'")
	}

	var status knox.VersionStatus
	switch strings.ToLower(*getVersionsState) {
	case "active":
		status = knox.Active
	case "primary":
		status = knox.Primary
	case "inactive":
		status = knox.Inactive
	}

	keyID := args[0]
	key, err := cli.GetKeyWithStatus(keyID, status)
	if err != nil {
		fatalf("Error getting key: %s", err.Error())
	}
	kvl := key.VersionList
	for _, v := range kvl {
		fmt.Printf("%d\n", v.ID)
	}
}
