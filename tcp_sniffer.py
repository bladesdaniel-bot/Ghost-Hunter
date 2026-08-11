# tcp_sniffer.py
"""
Middle-End Worker: Live Deep Packet Inspection using Wireshark Core
"""
import pyshark
import threading
import asyncio

class TCPSniffer:
    def __init__(self, callback_func, interface="Wi-Fi"):
        self.callback = callback_func
        self.is_sniffing = False
        self.thread = None
        self.interface = interface

    def _run_capture(self):
        # Pyshark requires a dedicated asynchronous event loop for background threading
        asyncio.set_event_loop(asyncio.new_event_loop())
        
        try:
            # Hook directly into Wireshark's engine using its native display filters
            capture = pyshark.LiveCapture(interface=self.interface, display_filter='tcp')
            
            for packet in capture.sniff_continuously():
                if not self.is_sniffing:
                    break
                    
                try:
                    src_ip = packet.ip.src
                    dst_ip = packet.ip.dst
                    src_port = packet.tcp.srcport
                    dst_port = packet.tcp.dstport
                    
                    # The Wireshark advantage: Identifying the exact protocol inside the payload
                    highest_layer = packet.highest_layer
                    
                    log_line = f"   [Wireshark DPI: {highest_layer}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}"
                    self.callback(log_line)
                except AttributeError:
                    # Silently pass if a packet is malformed or missing standard IP/TCP layers
                    continue
                    
        except Exception as e:
            self.callback(f"   [!] Wireshark Engine Error: {str(e)}\n   (Ensure Wireshark is installed and 'tshark' is in your Windows PATH)")

    def start(self):
        if not self.is_sniffing:
            self.is_sniffing = True
            self.thread = threading.Thread(target=self._run_capture, daemon=True)
            self.thread.start()

    def stop(self):
        self.is_sniffing = False
