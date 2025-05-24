// Author: D-Fault(www.github.com/TheFault666)
// SPUP, Jodhpur
package audit

import (
	"golang.org/x/sys/windows/registry"
)

func CheckUSBStatus() string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\USBSTOR`, registry.QUERY_VALUE)
	if err != nil {
		return "Unable to read USB status from registry."
	}
	defer key.Close()

	val, _, err := key.GetIntegerValue("Start")
	if err != nil {
		return "Could not determine USB status."
	}

	if val == 3 {
		return "USB Storage: Enabled"
	}
	return "USB Storage: Disabled"
}

//Author: D-Fault(www.github.com/TheFault666)
//SPUP, Jodhpur
