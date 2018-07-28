package api

import (
	"crypto/tls"
	flag "github.com/spf13/pflag"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-rootcerts"
)

const (
	// HTTPAddrEnvName defines an environment variable name which sets
	// the HTTP address if there is no -http-addr specified.
	HTTPAddrEnvName = "CONSUL_HTTP_ADDR"

	// HTTPTokenEnvName defines an environment variable name which sets
	// the HTTP token.
	HTTPTokenEnvName = "CONSUL_HTTP_TOKEN"

	// HTTPAuthEnvName defines an environment variable name which sets
	// the HTTP authentication header.
	HTTPAuthEnvName = "CONSUL_HTTP_AUTH"

	// HTTPSSLEnvName defines an environment variable name which sets
	// whether or not to use HTTPS.
	HTTPSSLEnvName = "CONSUL_HTTP_SSL"

	// HTTPCAFile defines an environment variable name which sets the
	// CA file to use for talking to Consul over TLS.
	HTTPCAFile = "CONSUL_CACERT"

	// HTTPCAPath defines an environment variable name which sets the
	// path to a directory of CA certs to use for talking to Consul over TLS.
	HTTPCAPath = "CONSUL_CAPATH"

	// HTTPClientCert defines an environment variable name which sets the
	// client cert file to use for talking to Consul over TLS.
	HTTPClientCert = "CONSUL_CLIENT_CERT"

	// HTTPClientKey defines an environment variable name which sets the
	// client key file to use for talking to Consul over TLS.
	HTTPClientKey = "CONSUL_CLIENT_KEY"

	// HTTPTLSServerName defines an environment variable name which sets the
	// server name to use as the SNI host when connecting via TLS
	HTTPTLSServerName = "CONSUL_TLS_SERVER_NAME"

	// HTTPSSLVerifyEnvName defines an environment variable name which sets
	// whether or not to disable certificate checking.
	HTTPSSLVerifyEnvName = "CONSUL_HTTP_SSL_VERIFY"
)

// Config is used to configure the creation of a client
type Config struct {
	// Address is the address of the Consul server
	Address string

	// Scheme is the URI scheme for the Consul server
	Scheme string

	// HttpAuth is the auth info to use for http access.
	HttpAuth HttpBasicAuth

	// WaitTime limits how long a Watch will block. If not provided,
	// the agent default values will be used.
	WaitTime time.Duration

	// Token is used to provide a per-request ACL token
	// which overrides the agent's default token.
	Token string

	TLSConfig TLSConfig
}

func (c *Config) Flags() *flag.FlagSet {
	fs := flag.NewFlagSet("", flag.ContinueOnError)

	fs.StringVar(&c.Address, "http-addr", "",
		"The address and port of the RESTful API backend.")
	fs.StringVarP(&c.HttpAuth.Username, "user", "u", "",
		"user to login")
	fs.StringVarP(&c.HttpAuth.Password, "password",  "p", "",
		"password for login")

	fs.StringVar(&c.TLSConfig.CAFile, "ca-file", "",
		"Path to a CA file to use for TLS.")
	fs.StringVar(&c.TLSConfig.CAPath, "ca-path", "",
		"Path to a directory of CA certificates.")
	fs.StringVar(&c.TLSConfig.CertFile, "client-cert", "",
		"Path to a client cert file to use for TLS.")
	fs.StringVar(&c.TLSConfig.KeyFile, "client-key", "",
		"Path to a client key file to use for TLS.")
	fs.StringVar(&c.TLSConfig.Address, "tls-server-name", "",
		"The server name to use as the SNI host when connecting via TLS.")
	fs.BoolVar(&c.TLSConfig.InsecureSkipVerify, "skip-verify", true,
		"Disable TLS host verification.")

	return fs
}

func (c *Config) APIClient() (*Client, error) {
	return NewClient(c)
}

// HttpBasicAuth is used to authenticate http client with HTTP Basic Authentication
type HttpBasicAuth struct {
	// Username to use for HTTP Basic Authentication
	Username string

	// Password to use for HTTP Basic Authentication
	Password string
}

// TLSConfig is used to generate a TLSClientConfig that's useful for talking to
// Consul using TLS.
type TLSConfig struct {
	// Address is the optional address of the Consul server. The port, if any
	// will be removed from here and this will be set to the ServerName of the
	// resulting config.
	Address string

	// CAFile is the optional path to the CA certificate used for Consul
	// communication, defaults to the system bundle if not specified.
	CAFile string

	// CAPath is the optional path to a directory of CA certificates to use for
	// Consul communication, defaults to the system bundle if not specified.
	CAPath string

	// CertFile is the optional path to the certificate for Consul
	// communication. If this is set then you need to also set KeyFile.
	CertFile string

	// KeyFile is the optional path to the private key for Consul communication.
	// If this is set then you need to also set CertFile.
	KeyFile string

	// InsecureSkipVerify if set to true will disable TLS host verification.
	InsecureSkipVerify bool
}

// DefaultConfig returns a default configuration for the client. By default this
// will pool and reuse idle connections to Consul. If you have a long-lived
// client object, this is the desired behavior and should make the most efficient
// use of the connections to Consul. If you don't reuse a client object , which
// is not recommended, then you may notice idle connections building up over
// time. To avoid this, use the DefaultNonPooledConfig() instead.
func DefaultConfig() *Config {
	config := &Config{
		Address:   "127.0.0.1:8100",
		Scheme:    "https",
	}

	if addr := os.Getenv(HTTPAddrEnvName); addr != "" {
		config.Address = addr
	}

	if token := os.Getenv(HTTPTokenEnvName); token != "" {
		config.Token = token
	}

	if auth := os.Getenv(HTTPAuthEnvName); auth != "" {
		var username, password string
		if strings.Contains(auth, ":") {
			split := strings.SplitN(auth, ":", 2)
			username = split[0]
			password = split[1]
		} else {
			username = auth
		}

		config.HttpAuth = HttpBasicAuth{
			Username: username,
			Password: password,
		}
	}

	if ssl := os.Getenv(HTTPSSLEnvName); ssl != "" {
		enabled, err := strconv.ParseBool(ssl)
		if err != nil {
			log.Printf("[WARN] client: could not parse %s: %s", HTTPSSLEnvName, err)
		}

		if enabled {
			config.Scheme = "https"
		}
	}

	if v := os.Getenv(HTTPTLSServerName); v != "" {
		config.TLSConfig.Address = v
	}
	if v := os.Getenv(HTTPCAFile); v != "" {
		config.TLSConfig.CAFile = v
	}
	if v := os.Getenv(HTTPCAPath); v != "" {
		config.TLSConfig.CAPath = v
	}
	if v := os.Getenv(HTTPClientCert); v != "" {
		config.TLSConfig.CertFile = v
	}
	if v := os.Getenv(HTTPClientKey); v != "" {
		config.TLSConfig.KeyFile = v
	}
	if v := os.Getenv(HTTPSSLVerifyEnvName); v != "" {
		doVerify, err := strconv.ParseBool(v)
		if err != nil {
			log.Printf("[WARN] client: could not parse %s: %s", HTTPSSLVerifyEnvName, err)
		}
		if !doVerify {
			config.TLSConfig.InsecureSkipVerify = true
		}
	}

	return config
}

// TLSConfig is used to generate a TLSClientConfig that's useful for talking to
// Consul using TLS.
func SetupTLSConfig(tlsConfig *TLSConfig) (*tls.Config, error) {
	tlsClientConfig := &tls.Config{
		InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
	}

	if tlsConfig.Address != "" {
		server := tlsConfig.Address
		hasPort := strings.LastIndex(server, ":") > strings.LastIndex(server, "]")
		if hasPort {
			var err error
			server, _, err = net.SplitHostPort(server)
			if err != nil {
				return nil, err
			}
		}
		tlsClientConfig.ServerName = server
	}

	if tlsConfig.CertFile != "" && tlsConfig.KeyFile != "" {
		tlsCert, err := tls.LoadX509KeyPair(tlsConfig.CertFile, tlsConfig.KeyFile)
		if err != nil {
			return nil, err
		}
		tlsClientConfig.Certificates = []tls.Certificate{tlsCert}
	}

	if tlsConfig.CAFile != "" || tlsConfig.CAPath != "" {
		rootConfig := &rootcerts.Config{
			CAFile: tlsConfig.CAFile,
			CAPath: tlsConfig.CAPath,
		}
		if err := rootcerts.ConfigureTLS(tlsClientConfig, rootConfig); err != nil {
			return nil, err
		}
	}

	return tlsClientConfig, nil
}
