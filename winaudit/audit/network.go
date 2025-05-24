// Author: D-Fault(www.github.com/TheFault666)
// SPUP, Jodhpur
package audit

import (
	"fmt"
	"net"
	"strings"
)

func GetNetworkDetails() (string, string) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "Failed to get network interfaces", "unknown"
	}

	var output string
	var selectedIP string

	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if strings.Contains(strings.ToLower(iface.Name), "virtual") || strings.Contains(strings.ToLower(iface.Name), "vpn") {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}
			if selectedIP == "" {
				selectedIP = ip.String()
			}
			output += fmt.Sprintf("Interface: %s\nIP Address: %s\n\n", iface.Name, ip)
		}
	}

	if output == "" {
		return "No Ethernet adapter found or system is offline.", "unknown"
	}

	return output, selectedIP
}

//Author: D-Fault(www.github.com/TheFault666)
//SPUP, Jodhpur
