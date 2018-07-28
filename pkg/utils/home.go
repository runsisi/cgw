package utils

import (
	"os"
	"path/filepath"

	"github.com/mitchellh/go-homedir"
)

// returns the current user's XDG config dir
func ConfigDir() string {
    configDir := os.Getenv("XDG_CONFIG_HOME")
    if configDir != "" {
        return configDir
    }

    homeDir, err := homedir.Dir()
	if err != nil {
		panic(err)
	}
    return filepath.Join(homeDir, ".config")
}
