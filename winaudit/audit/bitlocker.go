// Author: D-Fault(www.github.com/TheFault666)
package audit

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

// CheckBitLocker checks BitLocker status and returns a detailed string report.
func CheckBitLocker() string {
	psOutput, err := queryBitLockerPowerShell()
	if err == nil && strings.TrimSpace(psOutput) != "" {
		return formatBitLockerOutput(psOutput)
	}

	wmiOutput, wmiErr := queryBitLockerWMI()
	if wmiErr == nil && strings.TrimSpace(wmiOutput) != "" {
		return formatBitLockerOutput(wmiOutput)
	}

	return "Failed to retrieve BitLocker status."
}

// queryBitLockerPowerShell uses PowerShell to get BitLocker volume info with status
func queryBitLockerPowerShell() (string, error) {
	cmd := exec.Command("powershell", "-Command",
		`Get-BitLockerVolume | Select-Object MountPoint,VolumeType,ProtectionStatus | Format-Table -AutoSize`)

	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return "", err
	}

	return out.String(), nil
}

// queryBitLockerWMI fallback using WMIC CLI
func queryBitLockerWMI() (string, error) {
	cmd := exec.Command("wmic", "path", "Win32_EncryptableVolume", "get", "DeviceID,ProtectionStatus")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return "", err
	}

	return out.String(), nil
}

// formatBitLockerOutput formats the raw output to more human-readable form
func formatBitLockerOutput(output string) string {
	var builder strings.Builder
	builder.WriteString("BitLocker Status:\n\n")

	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Replace ProtectionStatus numbers with text if possible (PowerShell output)
		if strings.Contains(line, "ProtectionStatus") || strings.Contains(line, "MountPoint") {
			// header line, print as is
			builder.WriteString(line + "\n")
			continue
		}

		// Try to parse PowerShell output columns (MountPoint, VolumeType, ProtectionStatus)
		fields := strings.Fields(line)
		if len(fields) >= 3 {
			status := protectionStatusToText(fields[len(fields)-1])
			// Join all except last as volume info
			volumeInfo := strings.Join(fields[:len(fields)-1], " ")
			builder.WriteString(fmt.Sprintf("%s - %s\n", volumeInfo, status))
		} else if len(fields) == 2 {
			// fallback for WMIC output: DeviceID ProtectionStatus
			status := protectionStatusToText(fields[1])
			builder.WriteString(fmt.Sprintf("%s - %s\n", fields[0], status))
		} else {
			builder.WriteString(line + "\n")
		}
	}

	return builder.String()
}

// protectionStatusToText converts ProtectionStatus value to human-readable string
func protectionStatusToText(status string) string {
	switch status {
	case "1", "On", "2":
		return "Enabled"
	case "0", "Off", "0x0":
		return "Disabled"
	default:
		return "Unknown"
	}
}
//Author: D-Fault(www.github.com/TheFault666)
