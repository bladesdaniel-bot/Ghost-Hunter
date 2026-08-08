package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SecurityScanner represents our cybersecurity tool
type SecurityScanner struct {
	target string
	ports  []int
}

// PortScanResult holds information about a scanned port
type PortScanResult struct {
	Port    int
	Open    bool
	Service string
}

// VulnerabilityCheckResult holds vulnerability analysis results
type VulnerabilityCheckResult struct {
	Vulnerabilities []string
}

// NewSecurityScanner creates a new security scanner instance
func NewSecurityScanner(target string) *SecurityScanner {
	return &SecurityScanner{
		target: target,
		ports:  []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900},
	}
}

// scanPort scans a single port and returns if it's open
func (s *SecurityScanner) scanPort(host string, port int) bool {
	timeout := time.Second * 2
	conn, err := net.DialTimeout("tcp", host+":"+strconv.Itoa(port), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// scanPorts scans multiple ports concurrently
func (s *SecurityScanner) scanPorts(host string, ports []int) []PortScanResult {
	var results []PortScanResult
	var wg sync.WaitGroup

	// Create channel to collect results
	resultChan := make(chan PortScanResult, len(ports))

	// Limit concurrent goroutines
	semaphore := make(chan struct{}, 50) // Max 50 concurrent scans

	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}        // Acquire semaphore
			defer func() { <-semaphore }() // Release semaphore

			open := s.scanPort(host, p)

			// Determine service based on port
			service := s.getServiceName(p)

			resultChan <- PortScanResult{
				Port:    p,
				Open:    open,
				Service: service,
			}
		}(port)
	}

	// Close result channel when all goroutines are done
	go func() {
		wg.Wait()
		close(resultChan)
	}()

	// Collect results
	for result := range resultChan {
		results = append(results, result)
	}

	return results
}

// getServiceName returns the service name for a given port
func (s *SecurityScanner) getServiceName(port int) string {
	services := map[int]string{
		21:   "FTP",
		22:   "SSH",
		23:   "Telnet",
		25:   "SMTP",
		53:   "DNS",
		80:   "HTTP",
		110:  "POP3",
		111:  "RPC",
		135:  "RPC",
		139:  "NetBIOS",
		143:  "IMAP",
		443:  "HTTPS",
		445:  "SMB",
		993:  "IMAPS",
		995:  "POP3S",
		1433: "SQL Server",
		1521: "Oracle DB",
		3306: "MySQL",
		3389: "RDP",
		5432: "PostgreSQL",
		5900: "VNC",
	}

	if service, exists := services[port]; exists {
		return service
	}
	return "Unknown Service"
}

// checkVulnerabilities analyzes potential vulnerabilities
func (s *SecurityScanner) checkVulnerabilities(openPorts []int) VulnerabilityCheckResult {
	var vulnerabilities []string

	for _, port := range openPorts {
		switch port {
		case 21:
			vulnerabilities = append(vulnerabilities, "FTP server (port 21) - May be vulnerable to weak authentication")
		case 22:
			vulnerabilities = append(vulnerabilities, "SSH server (port 22) - Check for weak SSH configurations")
		case 80:
			vulnerabilities = append(vulnerabilities, "HTTP server (port 80) - Check for web application vulnerabilities")
		case 443:
			vulnerabilities = append(vulnerabilities, "HTTPS server (port 443) - Verify SSL/TLS configuration")
		case 23:
			vulnerabilities = append(vulnerabilities, "Telnet server (port 23) - Insecure plain text authentication")
		case 25:
			vulnerabilities = append(vulnerabilities, "SMTP server (port 25) - Check for open relay configuration")
		case 53:
			vulnerabilities = append(vulnerabilities, "DNS server (port 53) - Check for zone transfer vulnerabilities")
		}
	}

	return VulnerabilityCheckResult{
		Vulnerabilities: vulnerabilities,
	}
}

// networkDiscovery performs basic network discovery
func (s *SecurityScanner) networkDiscovery() map[string]string {
	info := make(map[string]string)

	host, err := os.Hostname()
	if err == nil {
		info["hostname"] = host
	} else {
		info["hostname"] = "Unknown"
	}

	ip, err := net.ResolveIPAddr("ip", s.target)
	if err == nil {
		info["ip_address"] = ip.IP.String()
	} else {
		info["ip_address"] = "Unable to resolve"
	}

	conn, err := net.DialTimeout("tcp", s.target+":80", time.Second*3)
	if err == nil {
		info["reachable"] = "true"
		conn.Close()
	} else {
		info["reachable"] = "false"
	}

	return info
}

// runComprehensiveScan runs a full security scan
func (s *SecurityScanner) runComprehensiveScan() {
	fmt.Println("============================================================")
	fmt.Println("SECURITY SCANNER - COMPREHENSIVE NETWORK ANALYSIS")
	fmt.Println("============================================================")
	fmt.Printf("Scan started: %s\n", time.Now().Format("2006-01-02 15:04:05"))
	fmt.Printf("Target: %s\n", s.target)
	fmt.Println("------------------------------------------------------------")

	fmt.Println("1. NETWORK DISCOVERY")
	networkInfo := s.networkDiscovery()
	for key, value := range networkInfo {
		fmt.Printf("   %s: %s\n", key, value)
	}
	fmt.Println()

	fmt.Println("2. PORT SCANNING")
	openPorts := []int{}
	results := s.scanPorts(s.target, s.ports)
	for _, result := range results {
		if result.Open {
			openPorts = append(openPorts, result.Port)
		}
	}

	if len(openPorts) > 0 {
		fmt.Printf("   Open ports found: %s\n", strings.Trim(strings.Join(strings.Fields(fmt.Sprint(openPorts)), ", "), "[]"))
	} else {
		fmt.Println("   No open ports found")
	}
	fmt.Println()

	fmt.Println("3. VULNERABILITY ANALYSIS")
	vulnResult := s.checkVulnerabilities(openPorts)
	if len(vulnResult.Vulnerabilities) > 0 {
		for _, vuln := range vulnResult.Vulnerabilities {
			fmt.Printf("   ⚠️  %s\n", vuln)
		}
	} else {
		fmt.Println("   No obvious vulnerabilities detected")
	}
	fmt.Println()

	fmt.Println("4. SERVICE DETECTION")
	for _, result := range results {
		if result.Open {
			fmt.Printf("   Port %d: %s\n", result.Port, result.Service)
		}
	}
	fmt.Println()

	fmt.Println("============================================================")
	fmt.Println("SCAN COMPLETE")
	fmt.Println("============================================================")
}

// blockIP uses the system firewall to instantly drop traffic from an IP
func (s *SecurityScanner) blockIP(ipAddress string) {
	fmt.Printf("Attempting to block IP: %s\n", ipAddress)

	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("netsh", "advfirewall", "firewall", "add", "rule", "name=Block_"+ipAddress, "dir=in", "action=block", "remoteip="+ipAddress)
	} else {
		cmd = exec.Command("sudo", "iptables", "-A", "INPUT", "-s", ipAddress, "-j", "DROP")
	}

	err := cmd.Run()
	if err != nil {
		fmt.Printf("❌ Failed to block IP. (Are you running this script as Root/Admin?) Error: %v\n", err)
	} else {
		fmt.Printf("✅ Successfully blocked %s!\n", ipAddress)
	}
}

// unblockIP removes the firewall rule
func (s *SecurityScanner) unblockIP(ipAddress string) {
	fmt.Printf("Attempting to unblock IP: %s\n", ipAddress)

	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name=Block_"+ipAddress)
	} else {
		cmd = exec.Command("sudo", "iptables", "-D", "INPUT", "-s", ipAddress, "-j", "DROP")
	}

	err := cmd.Run()
	if err != nil {
		fmt.Printf("❌ Failed to unblock IP. Error: %v\n", err)
	} else {
		fmt.Printf("✅ Successfully unblocked %s!\n", ipAddress)
	}
}

func main() {
	args := os.Args

	if len(args) < 2 {
		fmt.Println("Usage:")
		fmt.Println("  go run security_scanner.go <target> [--port <port1> <port2>] (Run scan)")
		fmt.Println("  go run security_scanner.go --block <IP>                      (Block IP)")
		fmt.Println("  go run security_scanner.go --unblock <IP>                    (Unblock IP)")
		os.Exit(1)
	}

	// 1. Handle Blocking/Unblocking Commands First
	if args[1] == "--block" {
		if len(args) < 3 {
			fmt.Println("❌ Please provide an IP address to block.")
			os.Exit(1)
		}
		scanner := NewSecurityScanner("")
		scanner.blockIP(args[2])
		return
	}

	if args[1] == "--unblock" {
		if len(args) < 3 {
			fmt.Println("❌ Please provide an IP address to unblock.")
			os.Exit(1)
		}
		scanner := NewSecurityScanner("")
		scanner.unblockIP(args[2])
		return
	}

	// 2. Handle Normal Scanning
	target := args[1]

	var specificPorts []int
	for i, arg := range args {
		if arg == "-p" || arg == "--port" {
			if i+1 < len(args) {
				for j := i + 1; j < len(args) && !strings.HasPrefix(args[j], "-"); j++ {
					port, err := strconv.Atoi(args[j])
					if err == nil {
						specificPorts = append(specificPorts, port)
					}
				}
			}
			break
		}
	}

	scanner := NewSecurityScanner(target)

	if len(specificPorts) > 0 {
		fmt.Printf("Scanning specific ports: %v\n", specificPorts)
		results := scanner.scanPorts(target, specificPorts)
		openPorts := []int{}
		for _, result := range results {
			if result.Open {
				openPorts = append(openPorts, result.Port)
			}
		}

		if len(openPorts) > 0 {
			fmt.Printf("Open ports: %v\n", openPorts)
		} else {
			fmt.Println("No open ports found")
		}
	} else {
		scanner.runComprehensiveScan()
	}
}
