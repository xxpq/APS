package httpx

import (
	"os"
	"path/filepath"
	"strings"
)

// FindIndexFile returns path if it is a regular file, otherwise looks
// for an index.html / index.htm in the directory and returns that. If
// none is found, returns the original path.
func FindIndexFile(path string) string {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return path
	}

	indexFiles := []string{"index.html", "index.htm"}
	for _, indexFile := range indexFiles {
		indexPath := filepath.Join(path, indexFile)
		if _, err := os.Stat(indexPath); err == nil {
			return indexPath
		}
	}
	return path
}

// ResolveFileURL resolves a file:// URL to a local filesystem path.
// Supports:
//   - file://www/wwwroot      -> /www/wwwroot (Unix) or C:\www\wwwroot (Windows)
//   - file://./www/wwwroot    -> resolved from CWD
//   - file://../www/wwwroot   -> resolved from CWD's parent
//   - file:///C:/www/wwwroot  -> Windows absolute path
func ResolveFileURL(fileURL string) (string, error) {
	localPath := strings.TrimPrefix(fileURL, "file://")

	// Relative path
	if strings.HasPrefix(localPath, "./") || strings.HasPrefix(localPath, "../") {
		cwd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		return filepath.Join(cwd, localPath), nil
	}

	// Windows absolute path like /C:/... -> strip leading /
	if strings.HasPrefix(localPath, "/") && len(localPath) > 2 && localPath[2] == ':' {
		return localPath[1:], nil
	}

	// Make sure the path is absolute
	if !filepath.IsAbs(localPath) {
		if !strings.HasPrefix(localPath, "/") {
			localPath = "/" + localPath
		}
	}
	return localPath, nil
}
