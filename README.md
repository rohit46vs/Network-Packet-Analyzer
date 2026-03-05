# Network Packet Analyzer

A beginner-friendly cybersecurity project that captures and analyzes live network traffic on your machine — just like Wireshark!

---

## Project Structure

```


├── packet_analyzer.py       # main file
└── README_packetanalyzer.md # This file
```

---

## Requirements

- Python 3.x
- Scapy library (install below)
- Administrator privileges on Windows

### Install Scapy:
```bash
pip install scapy
```

---

## How to Run

### Step 1 - Run VS Code as Administrator
- Close VS Code
- Right-click the VS Code icon
- Click "Run as Administrator"
- This is required to capture network packets on Windows!

### Step 2 - Open terminal and run:
```bash
python packet_analyzer.py
```

---

## Features

| Option | What it does |
|---|---|
| 1. Live Capture | Captures packets and displays them in real time |
| 2. Capture + Save | Same as above but saves everything to a log file |
| 3. Statistics | Shows breakdown of TCP / UDP / ICMP packets |
| 4. Learn Mode | Explains how packet analysis works |

---

## Example Output

```
  [14:32:01] TCP   192.168.1.5:52341 -> 142.250.74.46:443 | 66 bytes [SYN]
  [14:32:01] UDP   192.168.1.5:53    -> 8.8.8.8:53        | 74 bytes | DNS: google.com
  [14:32:02] TCP   192.168.1.5:52341 -> 142.250.74.46:443 | 60 bytes [ACK]
  [14:32:02] TCP   192.168.1.5:52342 -> 142.250.74.46:80  | 52 bytes [FIN]
```

---

## Understanding the Output

| Field | Meaning |
|---|---|
| Time | When the packet was captured |
| Protocol | TCP, UDP, ICMP, or OTHER |
| Source IP:Port | Where the packet came from |
| Dest IP:Port | Where the packet is going |
| Size | Packet size in bytes |
| Flags | TCP flags - SYN, ACK, FIN, RST etc. |
| DNS | Domain name being looked up (if any) |

---

## TCP Flags Explained

| Flag | Meaning |
|---|---|
| SYN | Starting a new connection |
| ACK | Acknowledging received data |
| FIN | Closing a connection |
| RST | Resetting / forcefully closing |
| PSH | Push data immediately |

---

## What You Learn From This Project

- What network packets are and how they work
- How TCP, UDP and ICMP protocols differ
- The TCP 3-way handshake (SYN, SYN-ACK, ACK)
- How DNS translates domain names to IP addresses
- How tools like Wireshark capture and display traffic
- Multi-threading and socket programming in Python
- How attackers sniff unencrypted traffic on HTTP sites

---

## How to Test It

1. Run the program and choose option 1
2. Open your browser and visit any website
3. Watch packets appear in real time in the terminal
4. You will see DNS queries, TCP connections, HTTP/HTTPS traffic
5. Press Ctrl+C to stop capturing early

---

## Security Note

> This tool is for educational purposes on YOUR OWN network only.
> Capturing network traffic without permission is illegal in most countries.
> All traffic to HTTPS sites is encrypted — you will see packets but not their content.

---