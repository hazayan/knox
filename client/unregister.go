package client

import (
	"errors"
	"fmt"
	"log"
)

var cmdUnregister = &Command{
	Run:       runUnregister,
	UsageLine: "unregister <key_identifier>",
	Short:     "unregister a key identifier from daemon",
	Long: `
Unregister stops cacheing and refreshing a specific key, deleting the associated files.

For more about knox, see https://github.com/hazayan/knox.

See also: knox register, knox daemon
	`,
}

func runUnregister(_ *Command, args []string) *ErrorStatus {
	if len(args) != 1 {
		return &ErrorStatus{errors.New("you must include a key ID to deregister. See 'knox help unregister'"), false}
	}
	k := NewKeysFile(daemonFolder + daemonToRegister)
	err := k.Lock()
	if err != nil {
		return &ErrorStatus{fmt.Errorf("error locking the register file: %s", err.Error()), false}
	}
	defer func() {
		if err := k.Unlock(); err != nil {
			log.Printf("Error unlocking register file: %v", err)
		}
	}()

	err = k.Remove([]string{args[0]})
	if err != nil {
		return &ErrorStatus{fmt.Errorf("error removing the key: %s", err.Error()), false}
	}
	log.Println("Unregistered key successfully")
	return nil
}
