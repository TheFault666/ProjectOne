// Author: D-Fault(www.github.com/TheFault666)
// SPUP, Jodhpur
package audit

import (
	"os/exec"
	"strings"
)

func CheckBitLocker() string {
	cmd := exec.Command("manage-bde", "-status")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return "Failed to retrieve BitLocker status. Ensure manage-bde is available."
	}

	volumes := strings.Split(string(output), "\r\n\r\n")
	result := "BitLocker Status:\n"
	for _, v := range volumes {
		if strings.Contains(v, "Volume") {
			result += v + "\n\n"
		}
	}
	return result
}

//Author: D-Fault(www.github.com/TheFault666)
//SPUP, Jodhpur
