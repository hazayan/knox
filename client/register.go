package client

func init() {
	cmdRegister.Run = runRegister
}

var cmdRegister = &Command{
	UsageLine: "register [-r] [-k identifier] [-f identifier_file]",
	Short:     "register keys to cache locally using daemon",
	Long: `
Register will cache the key in the file system and keep it up to date using the file system.

-r removes all existing registered keys.
-k specifies a specific key identifier to register
-f specifies a file containing a new line separated list of key identifiers

For a machine to access a certain key, it needs permissions on that key.

Note that knox register will only update the register file and will return successful
even if the machine does not have access to the key. The daemon will actually retrieve
the key.

For more about knox, see https://github.com/pinterest/knox.

See also: knox unregister, knox daemon
	`,
}

var registerRemove = cmdRegister.Flag.Bool("r", false, "")
var registerKey = cmdRegister.Flag.String("k", "", "")
var registerKeyFile = cmdRegister.Flag.String("f", "", "")

func runRegister(cmd *Command, args []string) {
	if *registerKey == "" && *registerKeyFile == "" {
		fatalf("You must include a key or key file to register. see 'knox help register'")
	}
	k := NewKeysFile(daemonFolder + daemonToRegister)

	var err error
	var ks []string
	if *registerKey == "" {
		f := NewKeysFile(*registerKeyFile)
		ks, err = f.Get()
		if err != nil {
			fatalf("There was an error reading input key file %s", err.Error())
		}
	} else {
		ks = []string{*registerKey}
	}

	err = k.Lock()
	if err != nil {
		fatalf("There was an error getting file lock %s", err.Error())
	}
	if *registerRemove {
		err = k.Overwrite(ks)
	} else {
		err = k.Add(ks)
	}

	if err != nil {
		k.Unlock()
		fatalf("There was an error registering keys %v: %s", ks, err.Error())
	}
	err = k.Unlock()
	if err != nil {
		errorf("There was an error unlocking register file: %s", err.Error())
	}
	logf("Successfully registered keys %v", ks)

}
