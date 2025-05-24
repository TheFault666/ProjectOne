// Author: D-Fault(www.github.com/TheFault666)
// SPUP, Jodhpur
package audit

import (
	"fmt"

	"github.com/StackExchange/wmi"
)

type Win32_BIOS struct {
	Manufacturer      string
	Name              string
	Version           string
	ReleaseDate       string
	SerialNumber      string
	SMBIOSBIOSVersion string
}

func GetBIOSDetails() string {
	var biosInfo []Win32_BIOS
	err := wmi.Query("SELECT Manufacturer, Name, Version, ReleaseDate, SerialNumber, SMBIOSBIOSVersion FROM Win32_BIOS", &biosInfo)
	if err != nil || len(biosInfo) == 0 {
		return "Could not retrieve BIOS information."
	}

	b := biosInfo[0]
	return fmt.Sprintf("Manufacturer: %s\nName: %s\nVersion: %s\nRelease Date: %s\nSerial Number: %s\nSMBIOS Version: %s",
		b.Manufacturer, b.Name, b.Version, b.ReleaseDate, b.SerialNumber, b.SMBIOSBIOSVersion)
}

//Author: D-Fault(www.github.com/TheFault666)
//SPUP, Jodhpur
