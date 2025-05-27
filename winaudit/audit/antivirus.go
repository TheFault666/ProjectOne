// Author: D-Fault(www.github.com/TheFault666)
package audit

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// AntiVirusProduct represents antivirus info (optional struct for parsing)
type AntiVirusProduct struct {
	DisplayName  string
	ProductState uint32
	ProductId    string
}

// GetAntivirusInfo returns antivirus details as a string
func GetAntivirusInfo() string {
	// Try PowerShell first (more reliable on modern Windows)
	psOutput, psErr := queryAvFromPowerShell()
	if psErr == nil && strings.TrimSpace(psOutput) != "" {
		return psOutput + getWindowsDefenderStatus(true) // assume third-party if PS shows AV
	}

	// Fallback to registry keys method
	avList, err := queryAvFromRegistry()
	if err != nil || len(avList) == 0 {
		return "Failed to retrieve antivirus information."
	}

	var builder strings.Builder
	builder.WriteString("Antivirus Products Detected (Registry):\n")
	for _, av := range avList {
		state := parseAVState(av.ProductState)
		builder.WriteString(fmt.Sprintf("- %s\n  ProductId: %s\n  Status: %s\n\n",
			av.DisplayName,
			av.ProductId,
			state))
	}

	// Add Windows Defender status, pass if any third party detected
	builder.WriteString(getWindowsDefenderStatus(len(avList) > 0))

	return builder.String()
}

// queryAvFromRegistry tries to read AV info from registry (simulate WMI SecurityCenter2)
func queryAvFromRegistry() ([]AntiVirusProduct, error) {
	keyPath := `SOFTWARE\Microsoft\Security Center\Provider\Av`
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, keyPath, registry.READ)
	if err != nil {
		return nil, err
	}
	defer key.Close()

	products := []AntiVirusProduct{}
	names, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return nil, err
	}

	for _, name := range names {
		subKey, err := registry.OpenKey(key, name, registry.READ)
		if err != nil {
			continue
		}
		displayName, _, err1 := subKey.GetStringValue("DisplayName")
		productState, _, err2 := subKey.GetIntegerValue("ProductState")
		productId, _, err3 := subKey.GetStringValue("ProductId")
		subKey.Close()

		if err1 != nil && err2 != nil && err3 != nil {
			continue
		}

		products = append(products, AntiVirusProduct{
			DisplayName:  displayName,
			ProductState: uint32(productState),
			ProductId:    productId,
		})
	}

	return products, nil
}

// parseAVState decodes the ProductState bits to human-readable string
func parseAVState(state uint32) string {
	if state&0x10 != 0 {
		return "Real-time protection enabled"
	}
	if state&0x01 != 0 {
		return "Enabled"
	}
	return "Disabled"
}

// queryAvFromPowerShell runs PowerShell command to get antivirus info as fallback
func queryAvFromPowerShell() (string, error) {
	cmd := exec.Command("powershell", "-Command",
		"Get-CimInstance -Namespace root\\SecurityCenter2 -ClassName AntivirusProduct | Format-List")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if err != nil {
		return "", err
	}

	return out.String(), nil
}

// getWindowsDefenderStatus returns defender info string
func getWindowsDefenderStatus(thirdPartyDetected bool) string {
	var builder strings.Builder
	builder.WriteString("- Windows Defender\n")

	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows Defender`, registry.READ)
	if err != nil {
		builder.WriteString("  Status: Not installed or inaccessible\n\n")
		return builder.String()
	}
	defer key.Close()

	if thirdPartyDetected {
		builder.WriteString("  Status: Installed but passive (disabled by third-party antivirus)\n\n")
		return builder.String()
	}

	disable, _, err := key.GetIntegerValue("DisableAntiSpyware")
	if err == nil && disable == 1 {
		builder.WriteString("  Status: Disabled\n\n")
		return builder.String()
	}

	rtpKey, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows Defender\Real-Time Protection`, registry.READ)
	if err != nil {
		builder.WriteString("  Status: Enabled (real-time unknown)\n\n")
		return builder.String()
	}
	defer rtpKey.Close()

	rtpDisabled, _, err := rtpKey.GetIntegerValue("DisableRealtimeMonitoring")
	if err != nil {
		builder.WriteString("  Status: Enabled (real-time unknown)\n\n")
		return builder.String()
	}

	if rtpDisabled == 0 {
		builder.WriteString("  Status: Enabled (Real-time protection ON)\n\n")
	} else {
		builder.WriteString("  Status: Enabled (Real-time protection OFF)\n\n")
	}

	return builder.String()
}
//Author: D-Fault(www.github.com/TheFault666)
