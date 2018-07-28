package api

import (
	"fmt"
	"io/ioutil"
)

type Cluster struct {
	c *Client
}

// Cluster returns a handle to the cluster endpoints
func (c *Client) Cluster() *Auth {
	return &Auth{c}
}

func (a *Auth) List() error {
	r := a.c.newRequest("GET", "/api/v2/cluster")
	r.header.Set("Content-Type", "application/json;charset=utf-8")
	r.header.Set("Accept", "application/json;charset=utf-8")
	_, resp, err := requireOK(a.c.doRequest(r))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	//var clusters string
	//if err := decodeBody(resp, &clusters); err != nil {
	//	return err
	//}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	fmt.Printf("%+v\n", string(body))

	fmt.Println("cookies:")
	for _, cookie := range a.c.HttpClient.Jar.Cookies(r.url) {
		fmt.Printf("  %s: %s\n", cookie.Name, cookie.Value)
	}

	return nil
}


