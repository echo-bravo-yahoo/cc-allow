package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// runSessionConfigPath prints the session config path and ensures its directory
// exists with a .gitignore. The path is not derivable outside cc-allow -
// findProjectRoot falls back to $HOME when no repo marker is closer, and the
// sessions dir moves with it - and the .gitignore is written here so a session
// grant never appears in `git status`. Matches what --init writes.
func runSessionConfigPath(sessionID string) ExitCode {
	if sessionID == "" {
		fmt.Fprintln(os.Stderr, "Error: no session id (pass --session or set CLAUDE_CODE_SESSION_ID)")
		return ExitError
	}
	if strings.ContainsAny(sessionID, `/\`) || strings.Contains(sessionID, "..") {
		fmt.Fprintln(os.Stderr, "Error: invalid session id")
		return ExitError
	}
	root := findProjectRoot()
	if root == "" {
		fmt.Fprintln(os.Stderr, "Error: no project root found; session configs need a project or $HOME ancestry")
		return ExitError
	}
	dir := filepath.Join(root, ".config", "cc-allow", "sessions")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		return ExitError
	}
	gitignore := filepath.Join(dir, ".gitignore")
	if _, err := os.Stat(gitignore); os.IsNotExist(err) {
		os.WriteFile(gitignore, []byte("*\n!.gitignore\n"), 0o644)
	}
	fmt.Println(filepath.Join(dir, sessionID+".toml"))
	return ExitAllow
}

// parseSessionMaxAge parses duration strings: "7d" -> 7*24h, or standard Go durations like "24h".
func parseSessionMaxAge(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		days := strings.TrimSuffix(s, "d")
		d, err := time.ParseDuration(days + "h")
		if err != nil {
			return 0, err
		}
		return d * 24, nil
	}
	return time.ParseDuration(s)
}

// cleanupSessionConfigs deletes session config files older than maxAge.
// Best-effort: errors are silently ignored.
func cleanupSessionConfigs(projectRoot string, maxAge time.Duration) {
	if projectRoot == "" {
		return
	}
	sessionsDir := filepath.Join(projectRoot, ".config", "cc-allow", "sessions")
	entries, err := os.ReadDir(sessionsDir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-maxAge)
	for _, entry := range entries {
		if entry.IsDir() || entry.Name() == ".gitignore" || !strings.HasSuffix(entry.Name(), ".toml") {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			continue
		}
		if info.ModTime().Before(cutoff) {
			os.Remove(filepath.Join(sessionsDir, entry.Name()))
		}
	}
}
