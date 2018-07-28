package api

import (
	"os"
	"path/filepath"

	"github.com/juju/persistent-cookiejar"
	"github.com/runsisi/cgw/pkg/utils"
)

func NewCookieJar() *cookiejar.Jar {
	jarFileDir := filepath.Join(utils.ConfigDir(), "calamari")

	os.MkdirAll(jarFileDir, 0775)

	jar, err := cookiejar.New(&cookiejar.Options{
		Filename: filepath.Join(jarFileDir, "cookies"),
	})
	if err != nil {
		panic(err)
	}
	return jar
}
