package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"
)

// Client provides a client to the Calamari API
type Client struct {
	Config

	HttpClient *http.Client
}

// NewClient returns a new client
func NewClient(config *Config) (*Client, error) {
	// bootstrap the config
	defConfig := DefaultConfig()

	if len(config.Address) == 0 {
		config.Address = defConfig.Address
	}

	if len(config.Scheme) == 0 {
		config.Scheme = defConfig.Scheme
	}

	if config.TLSConfig.Address == "" {
		config.TLSConfig.Address = defConfig.TLSConfig.Address
	}

	if config.TLSConfig.CAFile == "" {
		config.TLSConfig.CAFile = defConfig.TLSConfig.CAFile
	}

	if config.TLSConfig.CAPath == "" {
		config.TLSConfig.CAPath = defConfig.TLSConfig.CAPath
	}

	if config.TLSConfig.CertFile == "" {
		config.TLSConfig.CertFile = defConfig.TLSConfig.CertFile
	}

	if config.TLSConfig.KeyFile == "" {
		config.TLSConfig.KeyFile = defConfig.TLSConfig.KeyFile
	}

	if !config.TLSConfig.InsecureSkipVerify {
		config.TLSConfig.InsecureSkipVerify = defConfig.TLSConfig.InsecureSkipVerify
	}

	transport := cleanhttp.DefaultPooledTransport()
	httpClient, err := newHttpClient(transport, config.TLSConfig)
	if err != nil {
		return nil, err
	}

	parts := strings.SplitN(config.Address, "://", 2)
	if len(parts) == 2 {
		switch parts[0] {
		case "http":
			config.Scheme = "http"
		case "https":
			config.Scheme = "https"
		case "unix":
			transport = cleanhttp.DefaultTransport()
			transport.DialContext = func(_ context.Context, _, _ string) (net.Conn, error) {
				return net.Dial("unix", parts[1])
			}
			httpClient = &http.Client{
				Transport: transport,
			}
		default:
			return nil, fmt.Errorf("Unknown protocol scheme: %s", parts[0])
		}
		config.Address = parts[1]
	}

	if config.Token == "" {
		config.Token = defConfig.Token
	}

	return &Client{Config: *config, HttpClient: httpClient}, nil
}

// newRequest is used to create a new request
func (c *Client) newRequest(method, path string) *request {
	r := &request{
		method: method,
		url: &url.URL{
			Scheme: c.Config.Scheme,
			Host:   c.Config.Address,
			Path:   path,
		},
		params: make(map[string][]string),
		header: make(http.Header),
	}
	return r
}

// doRequest runs a request with our client
func (c *Client) doRequest(r *request) (time.Duration, *http.Response, error) {
	req, err := r.toHTTP()
	if err != nil {
		return 0, nil, err
	}
	start := time.Now()
	resp, err := c.HttpClient.Do(req)
	diff := time.Since(start)
	return diff, resp, err
}

// called by
// api/api.go/NewClient
// newHttpClient returns an http client configured with the given Transport and TLS
// config.
func newHttpClient(transport *http.Transport, tlsConfig TLSConfig) (*http.Client, error) {
	client := &http.Client{
		Transport: transport,
		Jar: NewCookieJar(),
	}

	if transport.TLSClientConfig == nil {
		tlsClientConfig, err := SetupTLSConfig(&tlsConfig)

		if err != nil {
			return nil, err
		}

		transport.TLSClientConfig = tlsClientConfig
	}

	return client, nil
}

// request is used to help build up a request
type request struct {
	method string
	url    *url.URL
	params url.Values
	body   io.Reader
	header http.Header
	obj    interface{}
	ctx    context.Context
}

// toHTTP converts the request to an HTTP request
func (r *request) toHTTP() (*http.Request, error) {
	// Encode the query parameters
	r.url.RawQuery = r.params.Encode()

	// Check if we should encode the body
	if r.body == nil && r.obj != nil {
		b, err := encodeBody(r.obj)
		if err != nil {
			return nil, err
		}
		r.body = b
	}

	// Create the HTTP request
	req, err := http.NewRequest(r.method, r.url.RequestURI(), r.body)
	if err != nil {
		return nil, err
	}

	req.URL.Host = r.url.Host
	req.URL.Scheme = r.url.Scheme
	req.Host = r.url.Host
	req.Header = r.header

	if r.ctx != nil {
		return req.WithContext(r.ctx), nil
	}

	return req, nil
}

// encodeBody is used to encode a request body
func encodeBody(obj interface{}) (io.Reader, error) {
	buf := bytes.NewBuffer(nil)
	enc := json.NewEncoder(buf)
	if err := enc.Encode(obj); err != nil {
		return nil, err
	}
	return buf, nil
}

// decodeBody is used to JSON decode a body
func decodeBody(resp *http.Response, out interface{}) error {
	dec := json.NewDecoder(resp.Body)
	return dec.Decode(out)
}

// requireOK is used to wrap doRequest and check for a 200
func requireOK(d time.Duration, resp *http.Response, e error) (time.Duration, *http.Response, error) {
	if e != nil {
		if resp != nil {
			resp.Body.Close()
		}
		return d, nil, e
	}
	if resp.StatusCode != 200 {
		var buf bytes.Buffer
		io.Copy(&buf, resp.Body)
		resp.Body.Close()
		return d, nil, fmt.Errorf("Unexpected response code: %d (%s)", resp.StatusCode, buf.Bytes())
	}
	return d, resp, nil
}
