package api

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/go-cleanhttp"
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

// QueryOptions are used to parameterize a query
type QueryOptions struct {
	// Providing a datacenter overwrites the DC provided
	// by the Config
	Datacenter string

	// AllowStale allows any Consul server (non-leader) to service
	// a read. This allows for lower latency and higher throughput
	AllowStale bool

	// RequireConsistent forces the read to be fully consistent.
	// This is more expensive but prevents ever performing a stale
	// read.
	RequireConsistent bool

	// WaitIndex is used to enable a blocking query. Waits
	// until the timeout or the next index is reached
	WaitIndex uint64

	// WaitHash is used by some endpoints instead of WaitIndex to perform blocking
	// on state based on a hash of the response rather than a monotonic index.
	// This is required when the state being blocked on is not stored in Raft, for
	// example agent-local proxy configuration.
	WaitHash string

	// WaitTime is used to bound the duration of a wait.
	// Defaults to that of the Config, but can be overridden.
	WaitTime time.Duration

	// Token is used to provide a per-request ACL token
	// which overrides the agent's default token.
	Token string

	// Near is used to provide a node name that will sort the results
	// in ascending order based on the estimated round trip time from
	// that node. Setting this to "_agent" will use the agent's node
	// for the sort.
	Near string

	// NodeMeta is used to filter results by nodes with the given
	// metadata key/value pairs. Currently, only one key/value pair can
	// be provided for filtering.
	NodeMeta map[string]string

	// RelayFactor is used in keyring operations to cause responses to be
	// relayed back to the sender through N other random nodes. Must be
	// a value from 0 to 5 (inclusive).
	RelayFactor uint8

	// Connect filters prepared query execution to only include Connect-capable
	// services. This currently affects prepared query execution.
	Connect bool

	// ctx is an optional context pass through to the underlying HTTP
	// request layer. Use Context() and WithContext() to manage this.
	ctx context.Context
}

func (o *QueryOptions) Context() context.Context {
	if o != nil && o.ctx != nil {
		return o.ctx
	}
	return context.Background()
}

func (o *QueryOptions) WithContext(ctx context.Context) *QueryOptions {
	o2 := new(QueryOptions)
	if o != nil {
		*o2 = *o
	}
	o2.ctx = ctx
	return o2
}

// WriteOptions are used to parameterize a write
type WriteOptions struct {
	// Providing a datacenter overwrites the DC provided
	// by the Config
	Datacenter string

	// Token is used to provide a per-request ACL token
	// which overrides the agent's default token.
	Token string

	// RelayFactor is used in keyring operations to cause responses to be
	// relayed back to the sender through N other random nodes. Must be
	// a value from 0 to 5 (inclusive).
	RelayFactor uint8

	// ctx is an optional context pass through to the underlying HTTP
	// request layer. Use Context() and WithContext() to manage this.
	ctx context.Context
}

func (o *WriteOptions) Context() context.Context {
	if o != nil && o.ctx != nil {
		return o.ctx
	}
	return context.Background()
}

func (o *WriteOptions) WithContext(ctx context.Context) *WriteOptions {
	o2 := new(WriteOptions)
	if o != nil {
		*o2 = *o
	}
	o2.ctx = ctx
	return o2
}

// QueryMeta is used to return meta data about a query
type QueryMeta struct {
	// LastIndex. This can be used as a WaitIndex to perform
	// a blocking query
	LastIndex uint64

	// LastContentHash. This can be used as a WaitHash to perform a blocking query
	// for endpoints that support hash-based blocking. Endpoints that do not
	// support it will return an empty hash.
	LastContentHash string

	// Time of last contact from the leader for the
	// server servicing the request
	LastContact time.Duration

	// Is there a known leader
	KnownLeader bool

	// How long did the request take
	RequestTime time.Duration

	// Is address translation enabled for HTTP responses on this agent
	AddressTranslationEnabled bool
}

// WriteMeta is used to return meta data about a write
type WriteMeta struct {
	// How long did the request take
	RequestTime time.Duration
}

// HttpBasicAuth is used to authenticate http client with HTTP Basic Authentication
type HttpBasicAuth struct {
	// Username to use for HTTP Basic Authentication
	Username string

	// Password to use for HTTP Basic Authentication
	Password string
}

// Config is used to configure the creation of a client
type Config struct {
	// Address is the address of the Consul server
	Address string

	// Scheme is the URI scheme for the Consul server
	Scheme string

	// Datacenter to use. If not provided, the default agent datacenter is used.
	Datacenter string

	// Transport is the Transport to use for the http client.
	Transport *http.Transport

	// HttpClient is the client to use. Default will be
	// used if not provided.
	HttpClient *http.Client

	// HttpAuth is the auth info to use for http access.
	HttpAuth *HttpBasicAuth

	// WaitTime limits how long a Watch will block. If not provided,
	// the agent default values will be used.
	WaitTime time.Duration

	// Token is used to provide a per-request ACL token
	// which overrides the agent's default token.
	Token string

	TLSConfig TLSConfig
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
		Address:   "127.0.0.1:8500",
		Scheme:    "http",
		Transport: cleanhttp.DefaultPooledTransport(),
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

		config.HttpAuth = &HttpBasicAuth{
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
