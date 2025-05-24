// Author: D-Fault(www.github.com/TheFault666)
// SPUP, Jodhpur
package audit

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var suspiciousFiles = []string{
	"crack.exe",
	"keygen.exe",
	"patch.exe",
	"Activator.exe",
	"kmspico.exe",
}

func CheckPiratedSoftware() string {
	programFiles := []string{
		os.Getenv("ProgramFiles"),
		os.Getenv("ProgramFiles(x86)"),
	}

	found := []string{}

	for _, dir := range programFiles {
		if dir == "" {
			continue
		}
		filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return nil
			}
			if !info.IsDir() {
				name := strings.ToLower(info.Name())
				for _, s := range suspiciousFiles {
					if strings.Contains(name, s) {
						found = append(found, path)
					}
				}
			}
			return nil
		})
	}

	if len(found) == 0 {
		return "No suspicious pirated software files found."
	}

	output := "Possible pirated software found:\n"
	for _, f := range found {
		output += fmt.Sprintf("- %s\n", f)
	}
	return output
}

//Author: D-Fault(www.github.com/TheFault666)
//SPUP, Jodhpur
