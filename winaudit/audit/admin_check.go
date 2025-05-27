// Author: D-Fault(www.github.com/TheFault666)
package audit

import (
	"golang.org/x/sys/windows"
)

func IsAdmin() bool {
	var sid *windows.SID
	// Create a SID for the Administrators group.
	sid, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}

	token := windows.Token(0)
	member, err := token.IsMember(sid)
	if err != nil {
		return false
	}
	return member
}

//Author: D-Fault(www.github.com/TheFault666)
