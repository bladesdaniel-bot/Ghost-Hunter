use etherparse::{InternetSlice, SlicedPacket, TransportSlice};
use pcap::{Capture, Device};
use rusqlite::Connection;
use std::collections::HashMap;
use std::io::{stdout, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// --- ANSI COLOR & EFFECT CONSTANTS ---
const COLOR_RESET: &str = "\x1b[0m";
const ANSI_BLINK: &str = "\x1b[5m";
const ANSI_BLINK_OFF: &str = "\x1b[25m";

const ALERT_CYAN: &str = "\x1b[36;1m";    // Recon: Port Scans
const ALERT_YELLOW: &str = "\x1b[33;1m";   // Warning: SYN Floods
const ALERT_MAGENTA: &str = "\x1b[35;1m";  // Attack: Brute Force
const ALERT_RED: &str = "\x1b[31;1m";      // Violation: Cleartext
const ALERT_FATAL: &str = "\x1b[41;37;5;1m"; // Breach: Reverse Shell

pub struct TcpSniffer {
    interface_name: String,
    is_sniffing: Arc<AtomicBool>,
}

impl TcpSniffer {
    /// Creates a new sniffer.
    pub fn new(interface: &str) -> Self {
        Self {
            interface_name: interface.to_string(),
            is_sniffing: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Starts the sniffing process in a background thread.
    pub fn start<F>(&mut self, callback: F)
    where
        F: Fn(String) + Send + 'static,
    {
        if self.is_sniffing.load(Ordering::SeqCst) {
            return;
        }

        self.is_sniffing.store(true, Ordering::SeqCst);
        let is_sniffing = Arc::clone(&self.is_sniffing);
        let interface = self.interface_name.clone();

        thread::spawn(move || {
            let conn = match Connection::open("packet_vault.db") {
                Ok(c) => c,
                Err(e) => {
                    callback(format!("   [!] SQLite Error: {}", e));
                    return;
                }
            };

            // OPTIMIZATION: Write-Ahead Logging
            if let Err(e) = conn.execute_batch(
                "PRAGMA journal_mode = WAL;
                 PRAGMA synchronous = NORMAL;
                 PRAGMA temp_store = MEMORY;"
            ) {
                callback(format!("   [!] SQLite Pragma Error: {}", e));
            }

            if let Err(e) = conn.execute(
                "CREATE TABLE IF NOT EXISTS packets (timestamp REAL, protocol TEXT, src_ip TEXT, src_port TEXT, dst_ip TEXT, dst_port TEXT)",
                [],
            ) {
                callback(format!("   [!] SQLite schema error: {}", e));
                return;
            }

            let mut active_flows: HashMap<String, u64> = HashMap::new();
            
            // --- THREAT TRACKERS ---
            let mut syn_tracker: HashMap<String, u64> = HashMap::new();
            let mut port_scan_tracker: HashMap<String, Vec<u16>> = HashMap::new();
            let mut brute_force_tracker: HashMap<String, u64> = HashMap::new();

            let mut cap = match Capture::from_device(interface.as_str())
                .unwrap()
                .promisc(true)
                .timeout(100)
                .open()
            {
                Ok(c) => c,
                Err(e) => {
                    callback(format!("   [!] Capture Engine Error: {}\n   (Ensure Npcap/WinPcap is installed on Windows, or run as root/sudo on Linux)", e));
                    return;
                }
            };

            if let Err(e) = cap.filter("tcp", true) {
                callback(format!("   [!] BPF Filter Error: {}", e));
                return;
            }

            while is_sniffing.load(Ordering::SeqCst) {
                match cap.next_packet() {
                    Ok(packet) => {
                        if let Ok(value) = SlicedPacket::from_ethernet(&packet.data) {
                            let mut src_ip = String::new();
                            let mut dst_ip = String::new();

                            if let Some(net) = value.ip {
                                match net {
                                    InternetSlice::Ipv4(ipv4, _) => {
                                        src_ip = ipv4.source_addr().to_string();
                                        dst_ip = ipv4.destination_addr().to_string();
                                    }
                                    InternetSlice::Ipv6(ipv6, _) => {
                                        src_ip = ipv6.source_addr().to_string();
                                        dst_ip = ipv6.destination_addr().to_string();
                                    }
                                }
                            }

                            let mut src_port = 0u16;
                            let mut dst_port = 0u16;
                            let protocol = "TCP";
                            
                            let mut syn_flag = false;
                            let mut ack_flag = false;
                            let mut payload: &[u8] = &[];

                            if let Some(transport) = value.transport {
                                if let TransportSlice::Tcp(tcp) = transport {
                                    src_port = tcp.source_port();
                                    dst_port = tcp.destination_port();
                                    syn_flag = tcp.syn();
                                    ack_flag = tcp.ack();
                                    payload = value.payload;
                                }
                            }

                            if src_ip.is_empty() || src_port == 0 {
                                continue;
                            }

                            let timestamp = SystemTime::now()
                                .duration_since(UNIX_EPOCH)
                                .unwrap()
                                .as_secs_f64();

                            let _ = conn.execute(
                                "INSERT INTO packets VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                                rusqlite::params![
                                    timestamp,
                                    protocol,
                                    src_ip,
                                    src_port.to_string(),
                                    dst_ip,
                                    dst_port.to_string()
                                ],
                            );

                            let flow_id = format!("{}:{}-{}:{}", src_ip, src_port, dst_ip, dst_port);
                            let count = active_flows.entry(flow_id.clone()).or_insert(0);
                            *count += 1;

                            // --- THREAT DETECTION LOGIC (WITH FLASHING IPS) ---

                            // 1. Cleartext Protocol Violation (FTP/Telnet)
                            if dst_port == 21 || dst_port == 23 || src_port == 21 || src_port == 23 {
                                callback(format!(
                                    "   [!!!] {}UNSAFE PROTOCOL DETECTED{}: {}{}{}{} -> {}:{}",
                                    ALERT_RED, COLOR_RESET, ANSI_BLINK, src_ip, ANSI_BLINK_OFF, COLOR_RESET, dst_ip, dst_port
                                ));
                            }
                            
                            // 2. SYN Flood (DoS)
                            if syn_flag && !ack_flag {
                                let syn_count = syn_tracker.entry(src_ip.clone()).or_insert(0);
                                *syn_count += 1;
                                if *syn_count > 100 && *syn_count % 100 == 1 {
                                    callback(format!(
                                        "   [!!!] {}SYN FLOOD DETECTED{} FROM {}{}{}{}",
                                        ALERT_YELLOW, COLOR_RESET, ANSI_BLINK, src_ip, ANSI_BLINK_OFF, COLOR_RESET
                                    ));
                                }
                            }

                            // 3. Port Scanning
                            let scanned_ports = port_scan_tracker.entry(src_ip.clone()).or_insert(Vec::new());
                            if !scanned_ports.contains(&dst_port) {
                                scanned_ports.push(dst_port);
                                if scanned_ports.len() > 15 && scanned_ports.len() % 15 == 1 {
                                    callback(format!(
                                        "   [!!!] {}PORT SCAN DETECTED{} FROM {}{}{}{}",
                                        ALERT_CYAN, COLOR_RESET, ANSI_BLINK, src_ip, ANSI_BLINK_OFF, COLOR_RESET
                                    ));
                                }
                            }

                            // 4. Brute Force Attempts (SSH, RDP, MySQL)
                            if (dst_port == 22 || dst_port == 3389 || dst_port == 3306) && *count == 1 {
                                let bf_count = brute_force_tracker.entry(src_ip.clone()).or_insert(0);
                                *bf_count += 1;
                                if *bf_count > 10 && *bf_count % 10 == 1 {
                                    callback(format!(
                                        "   [!!!] {}BRUTE FORCE ATTEMPT{} FROM {}{}{}{} ON PORT {}",
                                        ALERT_MAGENTA, COLOR_RESET, ANSI_BLINK, src_ip, ANSI_BLINK_OFF, COLOR_RESET, dst_port
                                    ));
                                }
                            }

                            // 5. Reverse Shell Detection (Payload Inspection)
                            if !payload.is_empty() {
                                let payload_str = String::from_utf8_lossy(payload).to_lowercase();
                                if payload_str.contains("cmd.exe") || payload_str.contains("/bin/bash") || payload_str.contains("powershell") {
                                    callback(format!(
                                        "   [!!!] {}REVERSE SHELL ACTIVE{} : {}{}{}{} -> {}",
                                        ALERT_FATAL, COLOR_RESET, ANSI_BLINK, src_ip, ANSI_BLINK_OFF, COLOR_RESET, dst_ip
                                    ));
                                }
                            }

                            // --- STANDARD LOGGING ---
                            if *count == 1 {
                                let log = format!("   [+] NEW FLOW: [{}] {}:{} -> {}:{}", protocol, src_ip, src_port, dst_ip, dst_port);
                                callback(log);
                            } else if *count % 100 == 0 {
                                let log = format!("   [~] ACTIVE FLOW: {} -> {} ({} packets)", src_ip, dst_ip, count);
                                callback(log);
                            }
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => {
                        continue;
                    }
                    Err(e) => {
                        callback(format!("   [!] Packet capture error: {}", e));
                        break;
                    }
                }
            }
        });
    }

    pub fn stop(&self) {
        self.is_sniffing.store(false, Ordering::SeqCst);
    }
}

fn main() {
    let devices = Device::list().unwrap();
    
    // Strict selection: Hunt specifically for the physical Wi-Fi adapter
    let default_device = devices.iter()
        .find(|d| {
            let desc = d.desc.as_deref().unwrap_or("");
            desc.contains("Wi-Fi") || desc.contains("Wireless")
        })
        .unwrap_or(&devices[0]);
    
    let mut sniffer = TcpSniffer::new(default_device.name.as_str());

    println!("Starting sniffer on {}... Press Ctrl+C to stop.", default_device.name);

    sniffer.start(|log_line| {
        println!("{}", log_line);
    });

    loop {
        thread::sleep(Duration::from_secs(1));
    }
}
