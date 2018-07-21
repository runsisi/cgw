package auth

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/spf13/cobra"
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
	Short:  "Login to api backend",
	Long: "Login to api backend",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		run(args)
	},
}

func init() {
	flags := LoginCmd.Flags()

	// https://tools.ietf.org/html/rfc6454#section-4
	flags.StringVar(&origin, "origin", "",
		"host for api backend")
	LoginCmd.MarkFlagRequired("origin")

	flags.StringVar(&user, "user", "", "user to login")
	LoginCmd.MarkFlagRequired("user")

	flags.StringVar(&password, "password",  "", "password for login")
	LoginCmd.MarkFlagRequired("password")
}

func run(args []string) error {
	if len(args) != 0 {
		return errors.New("invalid args")
	}

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

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

	clusterRequest.Header.Set("X-XSRF-TOKEN", authToken.Token)

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
