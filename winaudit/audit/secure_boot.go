// Author: D-Fault(www.github.com/TheFault666)
// SPUP, Jodhpur
package audit

import (
	"github.com/StackExchange/wmi"
)

type MS_SecureBoot struct {
	SecureBootEnabled bool
}

func CheckSecureBoot() string {
	var sb []MS_SecureBoot
	err := wmi.Query("SELECT SecureBootEnabled FROM MS_SecureBoot", &sb)
	if err != nil || len(sb) == 0 {
		return "Secure Boot status could not be determined (may not be supported on this system)."
	}

	if sb[0].SecureBootEnabled {
		return "Secure Boot: Enabled"
	}
	return "Secure Boot: Disabled"
}

//Author: D-Fault(www.github.com/TheFault666)
//SPUP, Jodhpur
