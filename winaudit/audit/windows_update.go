// Author: D-Fault(www.github.com/TheFault666)
// SPUP, Jodhpur
package audit

import (
	"fmt"
	"time"

	"golang.org/x/sys/windows/registry"
)

func CheckWindowsUpdate() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install`, registry.READ)
	if err != nil {
		return "Unable to retrieve Windows Update information."
	}
	defer key.Close()

	lastSuccessStr, _, err := key.GetStringValue("LastSuccessTime")
	if err != nil {
		return "Windows Update last success time not found."
	}

	// Parse time (format example: "2024-05-22 13:00:00")
	lastSuccess, err := time.Parse("2006-01-02 15:04:05", lastSuccessStr)
	if err != nil {
		return "Failed to parse last update timestamp."
	}

	diff := time.Since(lastSuccess)
	if diff.Hours() > 24*90 {
		return fmt.Sprintf("Last system update was over 3 months ago: %s", lastSuccess.Format(time.RFC1123))
	}

	return fmt.Sprintf("Last system update: %s (within last 3 months)", lastSuccess.Format(time.RFC1123))
}

//Author: D-Fault(www.github.com/TheFault666)
//SPUP, Jodhpur
