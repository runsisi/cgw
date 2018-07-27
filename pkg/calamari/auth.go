package calamari

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"path/filepath"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"time"

    "github.com/juju/persistent-cookiejar"
	"github.com/runsisi/cgw/pkg/utils"
	"github.com/spf13/cobra"
	"github.com/runsisi/cgw/pkg/calamari/api"
)

type Token struct {
	IssuedAt  time.Time `json:"IssuedAt"`
	ExpiresAt time.Time `json:"ExpiresAt"`
	Token     string    `json:"Token"`
}

var (
	origin string
	user string
	password string
)

var LoginCmd = &cobra.Command{
	Use:   "login",
	Short:  "Login to calamari backend",
	Long: "Login to calamari backend",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		run(args)
	},
}

func init() {
	flags := LoginCmd.Flags()

	config := api.Config{}
	apiFlags := api.Flags(&config)

	flags.AddFlagSet(apiFlags)

	// https://tools.ietf.org/html/rfc6454#section-4
	flags.StringVarP(&origin, "origin", "o", "",
		"base url for api backend")
	LoginCmd.MarkFlagRequired("origin")

	flags.StringVarP(&user, "user", "u", "",
		"user to login")
	LoginCmd.MarkFlagRequired("user")

	flags.StringVarP(&password, "password",  "p", "",
		"password for login")
	LoginCmd.MarkFlagRequired("password")
}

func newCookieJar() *cookiejar.Jar {
    jarFileDir := filepath.Join(utils.ConfigDir(), "leancloud")

    os.MkdirAll(jarFileDir, 0775)

    jar, err := cookiejar.New(&cookiejar.Options{
        Filename: filepath.Join(jarFileDir, "cookies"),
    })
    if err != nil {
        panic(err)
    }
    return jar
}

func run(args []string) error {
	if len(args) != 0 {
		return errors.New("invalid args")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	jar := newCookieJar()

	client := &http.Client{
	    Transport: tr,
	    Jar: jar,
	}

	// login
	loginUrl := fmt.Sprintf("%s%s", origin, "/api/v1/auth/login")

	authData := map[string]string{
		"username": user,
		"password": password,
	}

	buf := new(bytes.Buffer)
	err := json.NewEncoder(buf).Encode(authData)
	if err != nil {
		return err
	}

	loginReq, err := http.NewRequest("POST", loginUrl, buf)
	loginReq.Header.Set("Content-Type", "application/json;charset=utf-8")
	loginReq.Header.Set("Accept", "application/json;charset=utf-8")

	loginResp, err := client.Do(loginReq)
	if err != nil {
		log.Fatal("Do: ", err)
		return err
	}

	defer loginResp.Body.Close()

	loginBody, err := ioutil.ReadAll(loginResp.Body)
	if err != nil {
		log.Fatal("ReadAll: ", err)
		return err
	}

    fmt.Println("After 2nd request:")
    for _, cookie := range jar.Cookies(loginReq.URL) {
        fmt.Printf("  %s: %s\n", cookie.Name, cookie.Value)
    }

	fmt.Println(string(loginBody))

	var authToken Token
	// Decoder can only decode the whole structure, so we must use Unmarshal
	//dec := json.NewDecoder(loginResp.Body)
	//dec.Decode(authToken)
	json.Unmarshal(loginBody, &authToken)
	fmt.Printf("%+v", authToken)

	// cluster
	clusterUrl := fmt.Sprintf("%s%s", origin, "/api/v2/cluster")

	clusterRequest, err := http.NewRequest("GET", clusterUrl, nil)
	if err != nil {
		log.Fatal("NewRequest: ", err)
		return err
	}

	clusterResp, err := client.Do(clusterRequest)
	if err != nil {
		log.Fatal("Do: ", err)
		return err
	}

	defer clusterResp.Body.Close()

	clusterBody, err := ioutil.ReadAll(clusterResp.Body)
	if err != nil {
		log.Fatal("ReadAll: ", err)
		return err
	}

	fmt.Println(string(clusterBody))

	return nil
}
