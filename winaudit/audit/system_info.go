// Author: D-Fault(www.github.com/TheFault666)
// SPUP, Jodhpur
package audit

import (
	"fmt"
	"runtime"

	"github.com/shirou/gopsutil/host"
)

func GetSystemInfo() string {
	info, err := host.Info()
	if err != nil {
		return "Unable to retrieve system info."
	}

	return fmt.Sprintf(
		"Hostname: %s\nUptime: %d seconds\nOS: %s\nPlatform: %s\nKernel Version: %s\nArchitecture: %s",
		info.Hostname,
		info.Uptime,
		info.OS,
		info.Platform,
		info.KernelVersion,
		runtime.GOARCH,
	)
}

//Author: D-Fault(www.github.com/TheFault666)
//SPUP, Jodhpur
