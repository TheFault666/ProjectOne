// Author: D-Fault(www.github.com/TheFault666)
// SPUP, Jodhpur
package audit

import (
	"fmt"
	"os/exec"
	"os/user"
	"strings"
)

func GetUserDetails() string {
	current, err := user.Current()
	if err != nil {
		return "Unable to get current user."
	}

	out, err := exec.Command("net", "user").CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Current user: %s\nUnable to list all users.", current.Username)
	}

	users := []string{}
	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, "---") || strings.Contains(line, "User accounts") {
			continue
		}
		users = append(users, strings.Fields(line)...)
	}

	output := fmt.Sprintf("Current user: %s\n\nAll users and privileges:\n", current.Username)
	for _, u := range users {
		info, err := exec.Command("net", "user", u).CombinedOutput()
		if err == nil {
			output += fmt.Sprintf("\n%s:\n%s", u, string(info))
		}
	}

	return output
}

//Author: D-Fault(www.github.com/TheFault666)
//SPUP, Jodhpur
