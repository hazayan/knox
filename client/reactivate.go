package client

import (
	"errors"
	"fmt"
	"log"

	"github.com/hazayan/knox/pkg/types"
)

var cmdReactivate = &Command{
	Run:       runReactivate,
	UsageLine: "reactivate <key_identifier> <key_version>",
	Short:     "Reactivates an inactive key version",
	Long: `
Reactivate makes an inactive key version active.

Active keys are not used by default, but can still be used if the primary key fails.
Inactive keys should not be used for any purpose.

This command requires write access to the key.

For more about knox, see https://github.com/hazayan/knox.

See also: knox deactivate, knox promote
	`,
}

func runReactivate(_ *Command, args []string) *ErrorStatus {
	if len(args) != 2 {
		return &ErrorStatus{errors.New("reactivate takes exactly two argument. See 'knox help reactivate'"), false}
	}
	keyID := args[0]
	versionID := args[1]

	err := cli.UpdateVersion(keyID, versionID, types.Active)
	if err != nil {
		return &ErrorStatus{fmt.Errorf("error reactivating version: %s", err.Error()), true}
	}
	log.Printf("Reactivated %s successfully.\n", versionID)
	return nil
}
