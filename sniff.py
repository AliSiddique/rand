from scapy.all import sniff

def packet_callback(packet):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        print(f"Intercepted: {src_ip} -> {dst_ip}")
        if packet.haslayer("Raw"):
            try:
                print(f"  Data: {packet['Raw'].load[:50]}...")
            except:
                pass  # Skip if no readable data

interface = "en0"
print("Sniffing intercepted packets...")
sniff(iface=interface, prn=packet_callback, filter="ip")