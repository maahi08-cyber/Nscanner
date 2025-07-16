# NetworkScannerSuite 🔍🛡️

A Python-based tool for:
- 🔎 Port Scanning (Multi-threaded)
- 🧠 OS Detection (based on TTL & TCP headers)
- 📊 Real-time Network Traffic Monitoring

## Features

- Threaded port scanning with TCP connect
- OS fingerprinting via TCP/IP header analysis
- Live traffic statistics using `psutil`
- CLI with `argparse` for custom execution

## Requirements

```bash
pip install scapy psutil
```

## Usage

```bash
python network_scanner.py --ip 192.168.1.1 --scan --osdetect --monitor --start-port 1 --end-port 100 --duration 30
```

## Example Output

```
[OPEN] Port 22
[✓] Likely OS: Linux/Unix-based system
[12:10:05] Sent: 3.5 KB | Received: 12.8 KB
```
