package client

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path"

	"golang.org/x/crypto/ssh/terminal"
)

func init() {
	cmdLogin.Run = runLogin // break init cycle
}

var cmdLogin = &Command{
	UsageLine: "login [username]",
	Short:     "login as user and save authentication data",
	Long: `
Will authenticate user via OAuth2 password grant flow if available. Requires user to enter username and password. The authentication data is saved in "~/.knox_user_auth".

The optional username argument can specify the user that to log in as otherwise it uses the current os user.

For more about knox, see https://github.com/pinterest/knox.

See also: knox help auth
	`,
}

type authTokenResp struct {
	AccessToken string `json:"access_token"`
	Error       string `json:"error"`
}

func runLogin(cmd *Command, args []string) {
	var username string
	u, err := user.Current()
	if err != nil {
		fatalf("Error getting OS user:" + err.Error())
	}
	switch len(args) {
	case 0:
		username = u.Username
	case 1:
		username = args[0]
	default:
		fatalf("Invalid arguments. See 'knox login -h'")
	}

	fmt.Println("Please enter your password:")
	password, err := terminal.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		fatalf("Problem getting password:" + err.Error())
	}

	resp, err := http.PostForm(knoxOAuthTokenEndpoint,
		url.Values{
			"grant_type": {"password"},
			"client_id":  {knoxAuthClientID},
			"username":   {username},
			"password":   {string(password)},
		})
	if err != nil {
		fatalf("Error connecting to auth:" + err.Error())
	}
	var authResp authTokenResp
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fatalf("Failed to read data" + err.Error())
	}
	err = json.Unmarshal(data, &authResp)
	if err != nil {
		fatalf("Unexpected response from auth" + err.Error() + "data: " + string(data))
	}
	if authResp.Error != "" {
		fatalf("Fail to authenticate: %q", authResp.Error)
	}
	authFile := path.Join(u.HomeDir, "/.knox_user_auth")
	err = ioutil.WriteFile(authFile, data, 0600)
	if err != nil {
		fatalf("Failed to write auth data to file" + err.Error())
	}

}
