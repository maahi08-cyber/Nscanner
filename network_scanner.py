
import sys
import socket
import logging
import concurrent.futures
import time
import argparse
from scapy.all import *
import psutil
from datetime import datetime

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# -----------------------
# PORT SCANNER
# -----------------------

def scan_port(ip_address, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.5)
            result = sock.connect_ex((ip_address, port))
            if result == 0:
                return port
    except Exception:
        pass
    return None

def scan_ports(ip_address, start_port, end_port):
    print(f"\n[+] Starting port scan on {ip_address} from port {start_port} to {end_port}")
    open_ports = []
    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        future_to_port = {executor.submit(scan_port, ip_address, port): port for port in range(start_port, end_port + 1)}
        for future in concurrent.futures.as_completed(future_to_port):
            port = future_to_port[future]
            if future.result():
                open_ports.append(port)
                print(f"[OPEN] Port {port}")
    end_time = time.time()
    print(f"[✓] Port scan completed in {end_time - start_time:.2f} seconds.")
    return open_ports


# -----------------------
# OS DETECTION
# -----------------------

def detect_os(target_ip):
    print(f"\n[+] Starting OS detection on {target_ip}")
    try:
        syn_packet = IP(dst=target_ip) / TCP(dport=443, flags="S")
        response = sr1(syn_packet, timeout=2, verbose=0)

        if response is None:
            print("[!] No response received. Unable to detect OS.")
            return "Unknown"

        ip_ttl = response.ttl
        tcp_window_size = response.window

        if ip_ttl <= 64:
            if tcp_window_size <= 8192:
                detected_os = "Linux/Unix-based system"
            else:
                detected_os = "Possibly MacOS or BSD variant"
        elif ip_ttl > 64 and ip_ttl <= 128:
            detected_os = "Windows-based system"
        else:
            detected_os = "Unknown or obscured OS"

        print(f"[✓] Likely OS: {detected_os}")
        return detected_os

    except Exception as e:
        print(f"[!] Error during OS detection: {e}")
        return "Error"


# -----------------------
# REAL-TIME TRAFFIC MONITOR
# -----------------------

def monitor_traffic(interval=5, duration=30):
    print(f"\n[+] Monitoring real-time traffic for {duration} seconds (updates every {interval}s)")
    start_time = time.time()
    while time.time() - start_time < duration:
        net_io = psutil.net_io_counters()
        print(f"[{datetime.now().strftime('%H:%M:%S')}] Sent: {net_io.bytes_sent / 1024:.2f} KB | Received: {net_io.bytes_recv / 1024:.2f} KB")
        time.sleep(interval)
    print("[✓] Traffic monitoring complete.")


# -----------------------
# MAIN LOGIC
# -----------------------

def main():
    parser = argparse.ArgumentParser(description="Network Scanner Suite: Port Scanner + OS Detection + Traffic Monitor")
    parser.add_argument("--ip", required=True, help="Target IP address")
    parser.add_argument("--scan", action="store_true", help="Enable port scan")
    parser.add_argument("--osdetect", action="store_true", help="Enable OS detection")
    parser.add_argument("--monitor", action="store_true", help="Enable real-time traffic monitoring")
    parser.add_argument("--start-port", type=int, default=1, help="Start port for scanning")
    parser.add_argument("--end-port", type=int, default=1024, help="End port for scanning")
    parser.add_argument("--duration", type=int, default=30, help="Traffic monitoring duration (in seconds)")

    args = parser.parse_args()

    if args.scan:
        scan_ports(args.ip, args.start_port, args.end_port)

    if args.osdetect:
        detect_os(args.ip)

    if args.monitor:
        monitor_traffic(duration=args.duration)

if __name__ == "__main__":
    main()
