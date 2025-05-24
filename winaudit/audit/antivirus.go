// Author: D-Fault(www.github.com/TheFault666)
// SPUP, Jodhpur
package audit

import (
	"fmt"
	"strings"

	"github.com/StackExchange/wmi"
)

type AntiVirusProduct struct {
	DisplayName              string
	ProductState             uint32
	PathToSignedProductExe   string
	PathToSignedReportingExe string
	ProductUptoDate          bool
	ProductStateString       string
	ProductStateRaw          uint32
	ProductId                string
}

func GetAntivirusInfo() string {
	var avProducts []struct {
		DisplayName     string
		ProductState    uint32
		ProductUptoDate bool
		ProductId       string
	}

	// Query WMI namespace for AV info
	err := wmi.QueryNamespace("SELECT * FROM AntiVirusProduct", &avProducts, `root\SecurityCenter2`)
	if err != nil {
		return "Failed to retrieve antivirus information."
	}

	if len(avProducts) == 0 {
		return "No antivirus products detected."
	}

	var builder strings.Builder
	builder.WriteString("Antivirus Products Detected:\n")

	for _, av := range avProducts {
		state := parseAVState(av.ProductState)
		builder.WriteString(fmt.Sprintf("- %s\n  ProductId: %s\n  Status: %s\n  Up-to-date: %t\n\n",
			av.DisplayName,
			av.ProductId,
			state,
			av.ProductUptoDate,
		))
	}

	// Always include Windows Defender status via registry or WMI for completeness
	defenderStatus := getWindowsDefenderStatus()
	builder.WriteString(defenderStatus)

	return builder.String()
}

func parseAVState(state uint32) string {
	// productState bit flags (common states):
	// 0x10 = on (real-time protection enabled)
	// 0x01 = enabled
	// 0x00 = off or disabled
	// We simplify here for clarity
	if state&0x10 != 0 {
		return "Real-time protection enabled"
	}
	if state&0x01 != 0 {
		return "Enabled"
	}
	return "Disabled"
}

func getWindowsDefenderStatus() string {
	// Could be extended to query via WMI or registry for Defender status
	return "- Windows Defender\n  Status: (Status detection not implemented)\n"
}

//Author: D-Fault(www.github.com/TheFault666)
//SPUP, Jodhpur
