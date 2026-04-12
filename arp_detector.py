from scapy.all import sniff, ARP
from datetime import datetime
import csv
import sys

arp_table = {}
alerted_ips = set()
new_device_count = 0
spoof_alert_count = 0
log_file = "arp_log.csv"

INVALID_MACS = {
    "00:00:00:00:00:00",
    "ff:ff:ff:ff:ff:ff"
}

# Create CSV log file with header
with open(log_file, "w", newline="") as file:
    writer = csv.writer(file)
    writer.writerow(["Time", "Event", "IP Address", "Old MAC", "New MAC"])

def log_event(time_now, event, ip, old_mac, new_mac):
    with open(log_file, "a", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([time_now, event, ip, old_mac, new_mac])

def process_packet(packet):
    global new_device_count, spoof_alert_count

    if packet.haslayer(ARP) and packet[ARP].op == 2:   # ARP Reply only
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc.lower().strip()
        time_now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # Ignore invalid MAC addresses
        if mac in INVALID_MACS:
            return

        # New device detected
        if ip not in arp_table:
            arp_table[ip] = mac
            new_device_count += 1

            print(f"[{time_now}] [NEW DEVICE] {ip} -> {mac}")
            log_event(time_now, "New Device", ip, "-", mac)

        # MAC changed for same IP = possible ARP spoofing
        elif arp_table[ip] != mac:
            old_mac = arp_table[ip]

            if ip not in alerted_ips:
                spoof_alert_count += 1

                print(f"\n[{time_now}] ⚠ ARP SPOOFING DETECTED!")
                print(f"IP Address : {ip}")
                print(f"Old MAC    : {old_mac}")
                print(f"New MAC    : {mac}\n")

                log_event(time_now, "ARP Spoofing Detected", ip, old_mac, mac)
                alerted_ips.add(ip)

def show_summary():
    print("\n========== FINAL SUMMARY ==========")
    print(f"Total Devices Detected      : {new_device_count}")
    print(f"Total Spoofing Alerts       : {spoof_alert_count}")
    print(f"Unique IP-MAC Entries       : {len(arp_table)}")
    print(f"Log File                    : {log_file}")
    print("===================================\n")

print("Advanced Packet Sniffer Started...")
print("Monitoring ARP traffic for spoofing detection...")
print("Press CTRL + C to stop.\n")

try:
    sniff(iface="eth0", filter="arp", prn=process_packet, store=False)
except KeyboardInterrupt:
    print("\nStopping packet sniffing...")
    show_summary()
    sys.exit(0)
