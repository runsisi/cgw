package api

import (
	flag "github.com/spf13/pflag"
)

func Flags(c *Config) *flag.FlagSet {
	fs := flag.NewFlagSet("", flag.ContinueOnError)

	fs.StringVar(&c.Address, "http-addr", "",
		"The address and port of the RESTful API backend.")
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

	return fs
}
