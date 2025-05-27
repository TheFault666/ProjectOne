// Author: D-Fault(www.github.com/TheFault666)
package audit

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"time"

	"golang.org/x/sys/windows/registry"
)

func CheckWindowsUpdate() string {
	var builder strings.Builder

	// Check last successful update from registry
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install`, registry.READ)
	if err != nil {
		builder.WriteString("Unable to retrieve last Windows Update info.\n")
	} else {
		defer key.Close()
		lastSuccessStr, _, err := key.GetStringValue("LastSuccessTime")
		if err != nil {
			builder.WriteString("Last Windows Update success time not found.\n")
		} else {
			lastSuccess, err := time.Parse("2006-01-02 15:04:05", lastSuccessStr)
			if err != nil {
				builder.WriteString("Failed to parse last update timestamp.\n")
			} else {
				diff := time.Since(lastSuccess)
				if diff.Hours() > 24*90 {
					builder.WriteString(fmt.Sprintf("Last system update was over 3 months ago: %s\n", lastSuccess.Format(time.RFC1123)))
				} else {
					builder.WriteString(fmt.Sprintf("Last system update: %s (within last 3 months)\n", lastSuccess.Format(time.RFC1123)))
				}
			}
		}
	}

	// Check for pending updates using PowerShell
	cmd := exec.Command("powershell", "-Command", `
$Session = New-Object -ComObject Microsoft.Update.Session
$Searcher = $Session.CreateUpdateSearcher()
$SearchResult = $Searcher.Search("IsInstalled=0")
if ($SearchResult.Updates.Count -eq 0) {
    Write-Output "No pending updates found."
} else {
    Write-Output "Pending Updates Found:"
    foreach ($Update in $SearchResult.Updates) {
        Write-Output " - $($Update.Title)"
    }
}`)

	var psOut bytes.Buffer
	cmd.Stdout = &psOut
	cmd.Stderr = &psOut

	err = cmd.Run()
	if err != nil {
		builder.WriteString("\nFailed to query pending updates using PowerShell.\n")
	} else {
		builder.WriteString("\n" + psOut.String())
	}

	return builder.String()
}
//Author: D-Fault(www.github.com/TheFault666)
