package api

import (
	"fmt"
	"log"
	"time"

	"github.com/juju/persistent-cookiejar"
)

type Token struct {
	IssuedAt  time.Time `json:"IssuedAt"`
	ExpiresAt time.Time `json:"ExpiresAt"`
	Token     string    `json:"Token"`
}

type Auth struct {
	c *Client
}

// Auth returns a handle to the authentication endpoints
func (c *Client) Auth() *Auth {
	return &Auth{c}
}

func (a *Auth) Login() error {
	r := a.c.newRequest("POST", "/api/v1/auth/login")
	r.header.Set("Content-Type", "application/json;charset=utf-8")
	r.header.Set("Accept", "application/json;charset=utf-8")
	r.obj = map[string]string {
		"username": a.c.Config.HttpAuth.Username,
		"password": a.c.Config.HttpAuth.Password,
	}
	_, resp, err := requireOK(a.c.doRequest(r))
	if err != nil {
		log.Println(err)
		return err
	}
	defer resp.Body.Close()

	a.c.HttpClient.Jar.(* cookiejar.Jar).Save()

	var token Token
	if err := decodeBody(resp, &token); err != nil {
		return err
	}

	fmt.Printf("%+v\n", token)

	fmt.Println("cookies:")
	for _, cookie := range a.c.HttpClient.Jar.Cookies(r.url) {
		fmt.Printf("  %s: %s\n", cookie.Name, cookie.Value)
	}

	return nil
}


