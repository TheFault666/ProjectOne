// Author: D-Fault(www.github.com/TheFault666)
// SPUP, Jodhpur
package audit

import (
	"fmt"

	"github.com/StackExchange/wmi"
)

type Win32_OperatingSystem struct {
	Caption        string
	Version        string
	BuildNumber    string
	LastBootUpTime string
	InstallDate    string
}

func GetOSDetails() string {
	var result []Win32_OperatingSystem
	err := wmi.Query("SELECT Caption, Version, BuildNumber, LastBootUpTime, InstallDate FROM Win32_OperatingSystem", &result)
	if err != nil || len(result) == 0 {
		return "Could not retrieve OS details."
	}
	os := result[0]
	return fmt.Sprintf("Name: %s\nVersion: %s\nBuild: %s\nLast Boot: %s\nInstalled: %s",
		os.Caption,
		os.Version,
		os.BuildNumber,
		os.LastBootUpTime,
		os.InstallDate,
	)
}

//Author: D-Fault(www.github.com/TheFault666)
//SPUP, Jodhpur
