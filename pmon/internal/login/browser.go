package login

import (
	"fmt"
	"os/exec"
	"runtime"
)

// OpenBrowser attempts to open url in the user's default browser using the platform launcher. It returns an
// error if no such launcher is reachable (headless box, unsupported OS, PATH missing the tool) — the flow
// then hands the URL back for the user to open manually.
func OpenBrowser(url string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("no known browser launcher for platform %q", runtime.GOOS)
	}
	return cmd.Start()
}
