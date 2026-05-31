// Package buildinfo holds linker-injected release metadata (see scripts/build.sh).
package buildinfo

var (
	// Version is the SemVer release tag (e.g. v0.1.0) or "dev".
	Version = "dev"

	// Commit is the short git revision at build time.
	Commit = "unknown"
)
