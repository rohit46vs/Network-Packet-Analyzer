# ============================================
#   NETWORK PACKET ANALYZER
# ============================================

try:
    from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, DNSQR
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

import datetime
import os

stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0, "dns_queries": []}
log_file = None

def display_banner():
    print("\n" + "="*55)
    print("   NETWORK PACKET ANALYZER")
    print("="*55)
    print("   Project 4 - Cybersecurity Learning Series")
    print("="*55)

def display_menu():
    print("\n  [1] Start capturing packets")
    print("  [2] Capture and save to log file")
    print("  [3] View statistics")
    print("  [4] Learn how it works")
    print("  [5] Exit")

def get_protocol(packet):
    if packet.haslayer(TCP): return "TCP"
    elif packet.haslayer(UDP): return "UDP"
    elif packet.haslayer(ICMP): return "ICMP"
    else: return "OTHER"

def analyze_packet(packet):
    global stats, log_file
    if not packet.haslayer(IP): return

    stats["total"] += 1
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = get_protocol(packet)
    size = len(packet)
    timestamp = datetime.datetime.now().strftime("%H:%M:%S")

    if protocol == "TCP": stats["tcp"] += 1
    elif protocol == "UDP": stats["udp"] += 1
    elif protocol == "ICMP": stats["icmp"] += 1
    else: stats["other"] += 1

    src_port = dst_port = "-"
    if packet.haslayer(TCP):
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    dns_info = ""
    if packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            dns_query = packet[DNSQR].qname.decode(errors="ignore").rstrip(".")
            if dns_query not in stats["dns_queries"]:
                stats["dns_queries"].append(dns_query)
            dns_info = f" | DNS: {dns_query}"
        except: pass

    line = f"  [{timestamp}] {protocol:<5} {src_ip}:{src_port} -> {dst_ip}:{dst_port} | {size} bytes{dns_info}"
    print(line)
    if log_file:
        with open(log_file, "a") as f:
            f.write(line + "\n")

def start_capture(packet_count=50, save_log=False):
    global stats, log_file
    stats = {"total": 0, "tcp": 0, "udp": 0, "icmp": 0, "other": 0, "dns_queries": []}

    if save_log:
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = f"packet_log_{ts}.txt"
        print(f"\n  Saving to: {log_file}")
    else:
        log_file = None

    print(f"\n  Capturing {packet_count} packets... (Ctrl+C to stop)\n")
    try:
        sniff(prn=analyze_packet, count=packet_count, store=False)
    except KeyboardInterrupt:
        print("\n  Stopped by user.")
    except Exception as e:
        print(f"\n  Error: {e}")
        print("  Run VS Code as Administrator and try again!")
        return
    print("\n  Capture complete!")

def show_stats():
    total = stats["total"]
    if total == 0:
        print("\n  No packets yet. Run a capture first!")
        return
    print("\n" + "="*45)
    print("  CAPTURE STATISTICS")
    print("="*45)
    print(f"  Total : {total}")
    print(f"  TCP   : {stats['tcp']} ({stats['tcp']*100//total}%)")
    print(f"  UDP   : {stats['udp']} ({stats['udp']*100//total}%)")
    print(f"  ICMP  : {stats['icmp']} ({stats['icmp']*100//total}%)")
    if stats["dns_queries"]:
        print(f"\n  DNS Queries:")
        for q in stats["dns_queries"][:10]:
            print(f"    -> {q}")
    print("="*45)

def learn_mode():
    print("""
  WHAT IS A NETWORK PACKET?
  All internet data is split into small chunks called
  PACKETS - like splitting a book into many envelopes.

  Each packet has:
    Source IP, Destination IP, Protocol, Data, Size

  PROTOCOLS:
    TCP  -> Reliable delivery (websites, email)
    UDP  -> Fast, no guarantee (video, gaming, DNS)
    ICMP -> Ping / diagnostics

  TCP 3-WAY HANDSHAKE:
    Client -> SYN     -> Server  (Can we connect?)
    Client <- SYN-ACK <- Server  (Yes!)
    Client -> ACK     -> Server  (Connected!)

  This tool is a basic version of Wireshark!
  Only capture YOUR OWN network traffic!
    """)

def main():
    display_banner()
    if not SCAPY_AVAILABLE:
        print("\n  Scapy not installed! Run:\n\n      pip install scapy\n")
        input("  Press Enter to exit...")
        return

    print("\n  WARNING: Only capture traffic on YOUR OWN network!")
    print("  TIP: Run VS Code as Administrator!\n")

    while True:
        display_menu()
        choice = input("\n  Choose (1-5): ").strip()

        if choice == "1":
            try: count = int(input("  Packets to capture (default 50): ") or "50")
            except: count = 50
            start_capture(count, False)
            show_stats()
        elif choice == "2":
            try: count = int(input("  Packets to capture (default 50): ") or "50")
            except: count = 50
            start_capture(count, True)
            show_stats()
        elif choice == "3":
            show_stats()
        elif choice == "4":
            learn_mode()
        elif choice == "5":
            print("\n  Goodbye!\n")
            break
        else:
            print("  Invalid option.")
        input("\n  Press Enter to continue...")

if __name__ == "__main__":
    main()

