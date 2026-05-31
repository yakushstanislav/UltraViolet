// Package envsecret hydrates plain env vars from <NAME>_FILE pointers so the
// app can consume Docker/Kubernetes secrets without changing config schemas.
package envsecret

import (
	"fmt"
	"os"
	"strings"
)

// LoadFromFiles populates each plain env var from the file referenced by its
// _FILE companion when the plain var is unset.
//
// pairs maps plain var name to file var name, e.g.
// {"POSTGRES_PASSWORD": "POSTGRES_PASSWORD_FILE"}.
func LoadFromFiles(pairs map[string]string) error {
	for plain, fileEnv := range pairs {
		if os.Getenv(plain) != "" {
			continue
		}

		path := os.Getenv(fileEnv)
		if path == "" {
			continue
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("can't read %s from %s: %w", plain, fileEnv, err)
		}

		if err := os.Setenv(plain, strings.TrimRight(string(data), " \t\r\n")); err != nil {
			return fmt.Errorf("can't set %s: %w", plain, err)
		}
	}

	return nil
}
