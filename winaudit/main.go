// Author: D-Fault(www.github.com/TheFault666)
package main

import (
	"fmt"
	"log"
	"time"
	"winaudit/audit"
)

func printProgress(step, total int, message string) {
	percent := int(float64(step) / float64(total) * 100)
	barWidth := 40
	filled := int(float64(barWidth) * float64(step) / float64(total))
	bar := ""
	for i := 0; i < filled; i++ {
		bar += "="
	}
	for i := filled; i < barWidth; i++ {
		bar += " "
	}
	fmt.Printf("\r[%s] %3d%% - %s", bar, percent, message)
	if step == total {
		fmt.Println()
	}
}

func main() {
	totalSteps := 14
	currentStep := 0

	currentStep++
	printProgress(currentStep, totalSteps, "Checking admin privileges")
	if !audit.IsAdmin() {
		fmt.Println("\nPlease run the tool as Administrator.")
		return
	}

	currentStep++
	printProgress(currentStep, totalSteps, "Getting system info")
	systemInfo := audit.GetSystemInfo()

	currentStep++
	printProgress(currentStep, totalSteps, "Getting OS details")
	osDetails := audit.GetOSDetails()

	currentStep++
	printProgress(currentStep, totalSteps, "Getting user details")
	userDetails := audit.GetUserDetails()

	currentStep++
	printProgress(currentStep, totalSteps, "Getting network details")
	networkDetails, ip := audit.GetNetworkDetails()

	currentStep++
	printProgress(currentStep, totalSteps, "Checking USB storage access")
	usbStatus := audit.CheckUSBStatus()

	currentStep++
	printProgress(currentStep, totalSteps, "Checking BitLocker status")
	bitLocker := audit.CheckBitLocker()

	currentStep++
	printProgress(currentStep, totalSteps, "Getting BIOS details")
	biosDetails := audit.GetBIOSDetails()

	currentStep++
	printProgress(currentStep, totalSteps, "Checking Secure Boot")
	secureBoot := audit.CheckSecureBoot()

	currentStep++
	printProgress(currentStep, totalSteps, "Checking antivirus info")
	antivirus := audit.GetAntivirusInfo()

	currentStep++
	printProgress(currentStep, totalSteps, "Checking firewall info")
	firewall := audit.GenerateFirewallReport()

	currentStep++
	printProgress(currentStep, totalSteps, "Checking pirated software")
	pirated := audit.CheckPiratedSoftware()

	currentStep++
	printProgress(currentStep, totalSteps, "Checking software updates")
	updates := audit.CheckWindowsUpdate()

	currentStep++
	printProgress(currentStep, totalSteps, "Checking for outdated apps")
	outdated := audit.CheckOutdatedApps()

	currentStep++
	printProgress(currentStep, totalSteps, "Generating PDF report")
	err := audit.GeneratePDFReport(
		ip,
		systemInfo,
		osDetails,
		userDetails,
		networkDetails,
		usbStatus,
		bitLocker,
		biosDetails,
		secureBoot,
		antivirus,
		firewall,
		pirated,
		updates,
		outdated,
		time.Now(),
	)
	if err != nil {
		log.Fatalf("Failed to generate PDF report: %v", err)
	}

	fmt.Println("Security audit completed successfully.")
}

//Author: D-Fault(www.github.com/TheFault666)
