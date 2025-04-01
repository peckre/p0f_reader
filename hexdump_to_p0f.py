import os
import sys
import subprocess
from scapy.all import *
from tempfile import NamedTemporaryFile
import re

def clean_hexdump(hexdump):
    lines = hexdump.strip().splitlines()
    hex_data = ""
    for line in lines:
        parts = line.strip().split()
        if ':' in parts[0]:
            parts = parts[1:]
        hex_line = ''.join([p for p in parts if all(c in '0123456789abcdefABCDEF' for c in p)])
        hex_data += hex_line
    return bytes.fromhex(hex_data)

def save_pcap(packet):
    tmpfile = NamedTemporaryFile(delete=False, suffix=".pcap")
    wrpcap(tmpfile.name, [packet])
    return tmpfile.name

def run_p0f(pcap_path):
    try:
        result = subprocess.run(['sudo', 'p0f', '-r', pcap_path], capture_output=True, text=True)
        print(result.stdout)
    except FileNotFoundError:
        print("p0f is not installed or not in PATH.")

def build_packet_from_tcpdump(line):
    # Basic regex to extract fields
    match = re.search(r'(\S+) > (\S+), .*ttl (\d+),.* (\d+\.\d+\.\d+\.\d+)\.(\d+) > (\d+\.\d+\.\d+\.\d+)\.(\d+): S .*win (\d+).*<mss (\d+)>', line)
    if not match:
        print("Could not parse the tcpdump line. Make sure it's a SYN packet with MSS option.")
        sys.exit(1)

    src_mac, dst_mac, ttl, src_ip, src_port, dst_ip, dst_port, win_size, mss = match.groups()

    ether = Ether(src=src_mac, dst=dst_mac)
    ip = IP(src=src_ip, dst=dst_ip, ttl=int(ttl), flags='DF')
    tcp = TCP(sport=int(src_port), dport=int(dst_port), flags='S', window=int(win_size), options=[('MSS', int(mss))])

    packet = ether / ip / tcp
    return packet

def main():
    print("Choose input format:")
    print("1. Hexdump")
    print("2. tcpdump summary line")
    choice = input("Enter 1 or 2: ").strip()

    if choice == '1':
        print("Paste your hexdump below. End input with an empty line:")
        lines = []
        while True:
            line = input()
            if line.strip() == "":
                break
            lines.append(line)

        hex_input = '\n'.join(lines)
        try:
            packet_bytes = clean_hexdump(hex_input)
            packet = Ether(packet_bytes)
        except Exception as e:
            print(f"❌ Error: {e}")
            return

    elif choice == '2':
        print("Paste your tcpdump summary line:")
        line = input()
        packet = build_packet_from_tcpdump(line)

    else:
        print("Invalid choice.")
        return

    pcap_path = save_pcap(packet)
    print(f"✅ PCAP saved to: {pcap_path}")
    print("🔍 Running p0f...\n")
    run_p0f(pcap_path)
    os.unlink(pcap_path)

if __name__ == "__main__":
    main()
