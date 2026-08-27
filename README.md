# CyberSecurity Multi-Agent Infrastructure

An advanced, multi-language cybersecurity diagnostic and network analysis toolkit. This project utilizes a multi-agent architectural approach, delegating specific security tasks to specialized backend engines written in Go and Rust, all orchestrated by a sleek, animated Python holographic dashboard.

<video src="Final%20Video.mp4" autoplay loop muted playsinline width="100%"></video>

## 🏗️ System Architecture

This tool breaks down complex security operations into three distinct language environments to maximize speed, safety, and interface fluidity:

*   **Python (The Coordinator & UI):** Manages the graphical interface, handles background task threading, generates dynamic UI animations, and orchestrates the worker agents.
*   **Go (The Executioner):** Handles high-speed concurrent network operations, port scanning, and instant system-level firewall manipulation (blocking/unblocking IPs).
*   **Rust (The Sniffer):** Provides low-level, memory-safe, and lightning-fast TCP packet capture, threat signature detection, and packet logging using native OS interfaces (Npcap) and a bundled SQLite vault.

## ✨ Core Features

*   **Holographic GUI Dashboard:** Built with CustomTkinter, featuring real-time interactive threat consoles, clickable IP targeting, and custom multi-frame animations (breathing backgrounds, EKG pings, rotating shields).

*   **Floating Geolocation HUD:** Reroutes IP location telemetry into a dedicated, 90%-transparent floating popup window pinned to the top-right of the display. It automatically extracts GPS coordinates from the Go backend and features a dynamic, one-click button to open the target's physical location directly in Google Maps.

    <video src="Geo-Locatipn.mp4" autoplay loop muted playsinline width="100%"></video>

*   **Live TCP Packet Sniffing & Threat Detection:** Rust-powered packet capture that streams raw network telemetry to the Python UI, instantly flagging threat signatures including:
    *   SYN Floods (DoS attacks)
    *   Aggressive Port Scans
    *   Cleartext Protocol Violations (FTP/Telnet)
    *   Brute Force Attempts (SSH, RDP, MySQL)
    *   Reverse Shell Payloads (`cmd.exe`, `/bin/bash`, `powershell`)

    <video src="Different%20Kinds%20Of%20Attacks%20Alert.mp4" autoplay loop muted playsinline width="100%"></video>

*   **SQLite Packet Vault:** The Rust engine silently logs all intercepted packet metadata to a high-speed SQLite database (`packet_vault.db`) utilizing Write-Ahead Logging (WAL) for maximum I/O performance.

    *Before Adjustments:*
    <video src="Before%20Adjustments%20Were%20Made%20To%20Compile%20Tcp%20Packets.mp4" autoplay loop muted playsinline width="100%"></video>

    *After Adjustments:*
    <video src="After%20Adjustments%20Were%20Made%20To%20Compile%20Tcp%20Packets.mp4" autoplay loop muted playsinline width="100%"></video>

*   **Automated Firewall Control:** Instantly block or unblock active threats across the host operating system (Windows `netsh` or Linux `iptables`) using the Go binary.

    <video src="Blocked%20Ip%20And%20It%20Count%20Come%20Back%20Through%20Successfully.mp4" autoplay loop muted playsinline width="100%"></video>

*   **Comprehensive Vulnerability Probing:**
    *   High-Speed Port Scanning
    *   SSL Certificate validation
    *   HTTP security header audits
    *   DNS record extraction
    *   Deep vulnerability analysis via Nmap Scripting Engine (NSE) integration.

## 📂 Codebase Structure

*   `dashboard.py`: The main frontend entry point and UI orchestrator.
*   `vulnerability_checker.py`: Python engine for deep vulnerability probing and Nmap integration.
*   `config.py`: Centralized configuration for ports, timeouts, and headers.
*   `main.go`: The Go source code handling port scanning, pings, firewall rules, and geolocation.
*   `Cargo.toml`, `build.rs`, & `src/tcp_sniffer.rs`: The Rust backend utilizing `pcap`, `etherparse`, and `rusqlite` for live packet analysis.
*   **Animation Utilities:** Custom Python/Pillow scripts used to surgically remove backgrounds and generate multi-frame animations for the UI elements.
