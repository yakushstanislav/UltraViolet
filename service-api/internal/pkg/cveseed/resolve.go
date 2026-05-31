package cveseed

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// defaultDockerSeedPath is the conventional bind-mount location inside the
// uv-api / uv-scanner image. When CVE_CATALOG_SEED_FILE and CVE_CATALOG_SEED_DIR
// are empty, a non-empty file at this path is used without extra configuration.
const defaultDockerSeedPath = "/ServiceAPI/seed/cve-catalog.dump"

// ResolveSeedDump picks which pg_dump custom-format file to restore.
// Precedence: explicit CVE_CATALOG_SEED_FILE, then newest *.dump in
// CVE_CATALOG_SEED_DIR, then defaultDockerSeedPath if that file exists.
// Returns ("", "", nil) when nothing should be restored (no error, no logging).
func ResolveSeedDump(seedFile, seedDir string) (string, string, error) {
	if seedFile != "" {
		p, expandErr := expandSeedPath(seedFile)
		if expandErr != nil {
			return "", "", expandErr
		}

		return p, "CVE_CATALOG_SEED_FILE", nil
	}

	if seedDir != "" {
		d, expandErr := expandSeedPath(seedDir)
		if expandErr != nil {
			return "", "", expandErr
		}

		st, statErr := os.Stat(d)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				return "", "", fmt.Errorf("CVE_CATALOG_SEED_DIR does not exist: %s", d)
			}

			return "", "", fmt.Errorf("can't stat CVE_CATALOG_SEED_DIR: %w", statErr)
		}

		if !st.IsDir() {
			return "", "", fmt.Errorf("CVE_CATALOG_SEED_DIR is not a directory: %s", d)
		}

		p, pickErr := pickNewestDumpInDir(d)
		if pickErr != nil {
			return "", "", pickErr
		}

		if p == "" {
			return "", "", nil
		}

		return p, "CVE_CATALOG_SEED_DIR", nil
	}

	st, statErr := os.Stat(defaultDockerSeedPath)
	if statErr == nil && !st.IsDir() {
		return defaultDockerSeedPath, "default_mount", nil
	}

	return "", "", nil
}

func expandSeedPath(p string) (string, error) {
	if p == "" {
		return "", nil
	}

	if strings.HasPrefix(p, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("can't expand ~ in seed path: %w", err)
		}

		p = filepath.Join(home, p[2:])
	}

	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("can't absolutize seed path: %w", err)
	}

	return abs, nil
}

func pickNewestDumpInDir(dir string) (string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", fmt.Errorf("can't read CVE_CATALOG_SEED_DIR: %w", err)
	}

	var (
		bestPath string
		bestMod  int64 = -1
	)

	for _, e := range entries {
		if e.IsDir() {
			continue
		}

		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".dump") {
			continue
		}

		full := filepath.Join(dir, name)

		st, statErr := os.Stat(full)
		if statErr != nil {
			return "", fmt.Errorf("can't stat %s: %w", full, statErr)
		}

		mod := st.ModTime().UnixNano()
		if mod >= bestMod {
			bestMod = mod
			bestPath = full
		}
	}

	return bestPath, nil
}
