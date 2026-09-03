// Package version holds build-time version information, overridable via
// -ldflags "-X github.com/Dankular/Tunneld/internal/version.Version=...".
package version

var (
	// Version is the tunneld release version, or "dev" for unreleased builds.
	Version = "dev"
	// Commit is the git commit tunneld was built from, set by the release build.
	Commit = "unknown"
	// Date is the build timestamp, set by the release build.
	Date = "unknown"
)

// String returns a one-line "version (commit, date)" summary.
func String() string {
	return Version + " (" + Commit + ", " + Date + ")"
}
