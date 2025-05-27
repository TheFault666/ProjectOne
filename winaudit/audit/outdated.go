package audit

import (
	"bufio"
	"bytes"
	"os/exec"
	"runtime"
	"strings"
)

// CheckOutdatedApps attempts to identify outdated applications using winget or choco.
func CheckOutdatedApps() string {
	// Check OS version to determine if winget might be available
	if runtime.GOOS != "windows" {
		return "Outdated app check is only supported on Windows."
	}

	// Try using winget first
	result := checkWingetOutdated()
	if result != "" {
		return result
	}

	// Fallback to choco if winget fails or is not installed
	result = checkChocoOutdated()
	if result != "" {
		return result
	}

	// If neither tool is available, inform the user
	return "Neither 'winget' nor 'choco' found. To enable outdated app detection, install Chocolatey: https://chocolatey.org/install"
}

func checkWingetOutdated() string {
	cmd := exec.Command("powershell", "-Command", "winget upgrade --accept-source-agreements --disable-interactivity | Out-String")

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	output := out.String()

	if err != nil || strings.Contains(output, "not recognized") || strings.Contains(output, "No installed package") {
		return ""
	}

	if strings.Contains(output, "Name") && strings.Contains(output, "Id") {
		cleaned := cleanWingetOutput(output)
		return "Outdated applications (via winget):\n" + cleaned
	}
	return ""
}

func checkChocoOutdated() string {
	cmd := exec.Command("powershell", "-Command", "choco outdated")

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	output := out.String()
	if err != nil || strings.Contains(output, "not recognized") {
		return ""
	}

	if strings.Contains(output, "Chocolatey") && strings.Contains(output, "Outdated Packages") {
		return "Outdated applications (via Chocolatey):\n" + output
	}
	return ""
}

func cleanWingetOutput(output string) string {
	var cleanedLines []string
	scanner := bufio.NewScanner(strings.NewReader(output))

	progressIndicators := []string{
		"0%", "10%", "20%", "30%", "40%", "50%", "60%", "70%", "80%", "90%", "100%",
		"█", "│", "─", "|", "\\", "/", "-", "\r", "⣀", "⣶", "⠋", "⠙", "⠿",
	}

	artifactMap := map[string]string{
		"â–’": "", "â–ˆ": "", "â": "", "▒": "", "░": "", "█": "",
		"\u001b": "", // ANSI escape
	}

	for scanner.Scan() {
		line := scanner.Text()

		// Skip lines with progress indicators
		skip := false
		for _, p := range progressIndicators {
			if strings.Contains(line, p) {
				skip = true
				break
			}
		}
		if skip || strings.TrimSpace(line) == "" {
			continue
		}

		// Clean up Unicode artifacts
		for bad, good := range artifactMap {
			line = strings.ReplaceAll(line, bad, good)
		}

		cleanedLines = append(cleanedLines, line)
	}

	return strings.Join(cleanedLines, "\n")
}
