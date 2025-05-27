// Author: D-Fault(www.github.com/TheFault666)
// SPUP, Jodhpur
package audit

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Common ports to service name mapping
var portServiceMap = map[int]string{
	22:   "ssh",
	53:   "dns",
	80:   "http",
	443:  "https",
	3389: "rdp",
	445:  "microsoft-ds",
	135:  "rpc",
	139:  "netbios-ssn",
	3306: "mysql",
	5432: "postgresql",
	5900: "vnc",
	// add more as needed
}

// PortInfo stores info about an open port and associated process.
type PortInfo struct {
	Protocol     string
	LocalAddress string
	LocalPort    int
	PID          int
	ProcessName  string
	ServiceName  string
}

// CheckFirewallStatus returns whether Windows Firewall is enabled for each profile.
func CheckFirewallStatus() string {
	cmd := exec.Command("powershell", "-Command", "Get-NetFirewallProfile | Select-Object Name, Enabled | Format-Table -AutoSize")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return "Failed to retrieve firewall status."
	}
	return "Firewall Status:\n" + out.String()
}

// GetOpenPorts returns a slice of PortInfo for open/listening TCP and UDP ports.
func GetOpenPorts() ([]PortInfo, error) {
	tcpPorts, err := getTCPPorts()
	if err != nil {
		return nil, err
	}

	udpPorts, err := getUDPPorts()
	if err != nil {
		return nil, err
	}

	// Combine both slices
	return append(tcpPorts, udpPorts...), nil
}

func getTCPPorts() ([]PortInfo, error) {
	cmd := exec.Command("netstat", "-ano", "-p", "tcp")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to run netstat TCP: %v", err)
	}

	lines := strings.Split(out.String(), "\n")
	ports := []PortInfo{}

	re := regexp.MustCompile(`^ *TCP +([\d\.:]+):(\d+) +[\d\.:]+:\d+ +LISTENING +(\d+)$`)

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) == 4 {
			portNum, _ := strconv.Atoi(matches[2])
			pid, _ := strconv.Atoi(matches[3])
			serviceName := portServiceMap[portNum]
			ports = append(ports, PortInfo{
				Protocol:     "TCP",
				LocalAddress: matches[1],
				LocalPort:    portNum,
				PID:          pid,
				ServiceName:  serviceName,
			})
		}
	}

	pidMap, err := getProcessNames()
	if err != nil {
		return ports, fmt.Errorf("failed to get process names for TCP: %v", err)
	}

	for i, p := range ports {
		if name, ok := pidMap[p.PID]; ok {
			ports[i].ProcessName = name
		} else {
			ports[i].ProcessName = "Unknown"
		}
	}

	return ports, nil
}

func getUDPPorts() ([]PortInfo, error) {
	cmd := exec.Command("netstat", "-ano", "-p", "udp")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return nil, fmt.Errorf("failed to run netstat UDP: %v", err)
	}

	lines := strings.Split(out.String(), "\n")
	ports := []PortInfo{}

	re := regexp.MustCompile(`^ *UDP +([\d\.:]+):(\d+) +\*\:\* +(\d+)$`)

	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) == 4 {
			portNum, _ := strconv.Atoi(matches[2])
			pid, _ := strconv.Atoi(matches[3])
			serviceName := portServiceMap[portNum]
			ports = append(ports, PortInfo{
				Protocol:     "UDP",
				LocalAddress: matches[1],
				LocalPort:    portNum,
				PID:          pid,
				ServiceName:  serviceName,
			})
		}
	}

	pidMap, err := getProcessNames()
	if err != nil {
		return ports, fmt.Errorf("failed to get process names for UDP: %v", err)
	}

	for i, p := range ports {
		if name, ok := pidMap[p.PID]; ok {
			ports[i].ProcessName = name
		} else {
			ports[i].ProcessName = "Unknown"
		}
	}

	return ports, nil
}

// getProcessNames returns a map of PID -> process name.
func getProcessNames() (map[int]string, error) {
	cmd := exec.Command("powershell", "-Command", "Get-Process | Select-Object Id, ProcessName | Format-Table -HideTableHeaders")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err != nil {
		return nil, err
	}

	pidMap := make(map[int]string)
	scanner := bufio.NewScanner(&out)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		pid, err := strconv.Atoi(fields[0])
		if err != nil {
			continue
		}
		processName := fields[1]
		pidMap[pid] = processName
	}
	return pidMap, nil
}

// GenerateFirewallReport generates a string report for firewall and open ports.
func GenerateFirewallReport() string {
	firewallStatus := CheckFirewallStatus()

	openPorts, err := GetOpenPorts()
	var portsReport string
	if err != nil {
		portsReport = "Failed to get open ports: " + err.Error()
	} else if len(openPorts) == 0 {
		portsReport = "No open TCP/UDP ports found."
	} else {
		var sb strings.Builder
		sb.WriteString("Open TCP/UDP Ports:\n")
		for _, p := range openPorts {
			serviceInfo := ""
			if p.ServiceName != "" {
				serviceInfo = fmt.Sprintf(" (%s)", p.ServiceName)
			}
			sb.WriteString(fmt.Sprintf("- %s %s:%d PID: %d (%s)%s\n",
				p.Protocol, p.LocalAddress, p.LocalPort, p.PID, p.ProcessName, serviceInfo))
		}
		portsReport = sb.String()
	}

	return fmt.Sprintf("%s\n\n%s", firewallStatus, portsReport)
}
