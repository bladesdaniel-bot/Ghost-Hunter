# tcp_sniffer.py
"""
Middle-End Worker: Live Deep Packet Inspection using Wireshark Core
"""
import pyshark
import threading
import asyncio
import sqlite3
import time

class TCPSniffer:
    def __init__(self, callback_func, interface="Wi-Fi"):
        self.callback = callback_func
        self.is_sniffing = False
        self.thread = None
        self.interface = interface
        self.active_flows = {}  # Upgrade 2: Flow Tracker
        self._setup_database()  # Upgrade 3: SQLite Vault

    def _setup_database(self):
        # check_same_thread=False allows background sniffing to write freely
        self.conn = sqlite3.connect('packet_vault.db', check_same_thread=False)
        self.cursor = self.conn.cursor()
        self.cursor.execute('''CREATE TABLE IF NOT EXISTS packets 
                             (timestamp REAL, protocol TEXT, src_ip TEXT, src_port TEXT, dst_ip TEXT, dst_port TEXT)''')
        self.conn.commit()

    def _run_capture(self):
        # Pyshark requires a dedicated asynchronous event loop for background threading
        asyncio.set_event_loop(asyncio.new_event_loop())
        
        try:
            # Hook directly into Wireshark's engine using OS-level kernel filtering (Much faster)
            capture = pyshark.LiveCapture(interface=self.interface, bpf_filter='tcp')

            try:
                for packet in capture.sniff_continuously():
                    if not self.is_sniffing:
                        break
                        
                    # Safer pythonic validation instead of relying on forced exceptions
                    if hasattr(packet, 'ip') and hasattr(packet, 'tcp'):
                        src_ip = packet.ip.src
                        dst_ip = packet.ip.dst
                        src_port = packet.tcp.srcport
                        dst_port = packet.tcp.dstport
                        
                        # Structure the data so local AI agents can easily parse it as JSON later
                        packet_data = {
                            "protocol": packet.highest_layer,
                            "src_ip": src_ip,
                            "src_port": src_port,
                            "dst_ip": dst_ip,
                            "dst_port": dst_port
                        }
                        
                        # Upgrade 3: SQLite Packet Vault Logging
                        self.cursor.execute("INSERT INTO packets VALUES (?, ?, ?, ?, ?, ?)", 
                                           (time.time(), packet_data['protocol'], packet_data['src_ip'], 
                                            packet_data['src_port'], packet_data['dst_ip'], packet_data['dst_port']))
                        self.conn.commit()

                        # Upgrade 2: Connection Deduplication
                        flow_id = f"{src_ip}:{src_port}-{dst_ip}:{dst_port}"
                        
                        if flow_id not in self.active_flows:
                            self.active_flows[flow_id] = 1
                            # Send initial connection directly to the dashboard
                            log_line = f"   [+] NEW FLOW: [{packet_data['protocol']}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                            self.callback(log_line)
                        else:
                            self.active_flows[flow_id] += 1
                            # Throttle dashboard updates for active flows to kill terminal spam
                            if self.active_flows[flow_id] % 100 == 0:
                                log_line = f"   [~] ACTIVE FLOW: {src_ip} -> {dst_ip} ({self.active_flows[flow_id]} packets)"
                                self.callback(log_line)

            finally:
                # CRITICAL: Explicitly close the capture to kill the hidden tshark.exe process
                capture.close()
                    
        except Exception as e:
            self.callback(f"   [!] Wireshark Engine Error: {str(e)}\n   (Ensure Wireshark is installed and 'tshark' is in your Windows PATH)")

    def start(self):
        if not self.is_sniffing:
            self.is_sniffing = True
            self.thread = threading.Thread(target=self._run_capture, daemon=True)
            self.thread.start()

    def stop(self):
        self.is_sniffing = False
