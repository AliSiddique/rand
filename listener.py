import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import datetime
import socket
import struct
import textwrap
from scapy.all import sniff, IP, TCP, UDP, ICMP, Ether, ARP

class PacketVisualizer:
    def __init__(self, root):
        self.root = root
        self.root.title("Network Packet Visualizer")
        self.root.geometry("1200x700")
        self.root.minsize(800, 600)
        
        self.is_capturing = False
        self.capture_thread = None
        self.packets_captured = 0
        self.packet_types = {'TCP': 0, 'UDP': 0, 'ICMP': 0, 'ARP': 0, 'Other': 0}
        self.packet_data = []
        
        self.create_widgets()
        self.create_menu()
        
    def create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Start Capture", command=self.start_capture)
        file_menu.add_command(label="Stop Capture", command=self.stop_capture)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Control frame
        control_frame = ttk.LabelFrame(main_frame, text="Capture Controls")
        control_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Buttons
        btn_frame = ttk.Frame(control_frame)
        btn_frame.pack(fill=tk.X, padx=10, pady=10)
        
        self.start_btn = ttk.Button(btn_frame, text="Start Capture", command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        self.stop_btn = ttk.Button(btn_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        self.clear_btn = ttk.Button(btn_frame, text="Clear Display", command=self.clear_display)
        self.clear_btn.pack(side=tk.LEFT, padx=5)
        
        # Interface selection
        iface_frame = ttk.Frame(control_frame)
        iface_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Label(iface_frame, text="Network Interface:").pack(side=tk.LEFT, padx=(0, 5))
        self.iface_var = tk.StringVar(value="")
        self.iface_entry = ttk.Entry(iface_frame, textvariable=self.iface_var, width=20)
        self.iface_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(iface_frame, text="(Leave blank for all interfaces)").pack(side=tk.LEFT, padx=5)
        
        # Filter
        filter_frame = ttk.Frame(control_frame)
        filter_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Label(filter_frame, text="BPF Filter:").pack(side=tk.LEFT, padx=(0, 5))
        self.filter_var = tk.StringVar(value="")
        self.filter_entry = ttk.Entry(filter_frame, textvariable=self.filter_var, width=40)
        self.filter_entry.pack(side=tk.LEFT, padx=5)
        ttk.Label(filter_frame, text="(e.g., 'tcp port 80' or 'icmp')").pack(side=tk.LEFT, padx=5)
        
        # Status bar
        status_frame = ttk.Frame(control_frame)
        status_frame.pack(fill=tk.X, padx=10, pady=(0, 10))
        
        ttk.Label(status_frame, text="Status:").pack(side=tk.LEFT, padx=(0, 5))
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(status_frame, textvariable=self.status_var).pack(side=tk.LEFT, padx=5)
        
        ttk.Label(status_frame, text="Packets:").pack(side=tk.LEFT, padx=(20, 5))
        self.packet_count_var = tk.StringVar(value="0")
        ttk.Label(status_frame, textvariable=self.packet_count_var).pack(side=tk.LEFT, padx=5)
        
        # Packet statistics frame
        stats_frame = ttk.LabelFrame(main_frame, text="Packet Statistics")
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Grid layout for packet type statistics
        for i, packet_type in enumerate(['TCP', 'UDP', 'ICMP', 'ARP', 'Other']):
            ttk.Label(stats_frame, text=f"{packet_type}:").grid(row=0, column=i*2, padx=(10 if i == 0 else 5, 5), pady=10, sticky=tk.E)
            
            var_name = f"{packet_type.lower()}_count_var"
            setattr(self, var_name, tk.StringVar(value="0"))
            ttk.Label(stats_frame, textvariable=getattr(self, var_name)).grid(row=0, column=i*2+1, padx=(0, 10), pady=10, sticky=tk.W)
        
        # Data display notebook
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill=tk.BOTH, expand=True)
        
        # Packet list frame
        packet_list_frame = ttk.Frame(notebook)
        notebook.add(packet_list_frame, text="Packet List")
        
        # Treeview for packet list
        columns = ('No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info')
        self.packet_tree = ttk.Treeview(packet_list_frame, columns=columns, show='headings')
        
        # Configure columns
        self.packet_tree.heading('No.', text='No.')
        self.packet_tree.heading('Time', text='Time')
        self.packet_tree.heading('Source', text='Source')
        self.packet_tree.heading('Destination', text='Destination')
        self.packet_tree.heading('Protocol', text='Protocol')
        self.packet_tree.heading('Length', text='Length')
        self.packet_tree.heading('Info', text='Info')
        
        self.packet_tree.column('No.', width=50, anchor=tk.CENTER)
        self.packet_tree.column('Time', width=140, anchor=tk.CENTER)
        self.packet_tree.column('Source', width=140, anchor=tk.CENTER)
        self.packet_tree.column('Destination', width=140, anchor=tk.CENTER)
        self.packet_tree.column('Protocol', width=80, anchor=tk.CENTER)
        self.packet_tree.column('Length', width=60, anchor=tk.CENTER)
        self.packet_tree.column('Info', width=300)
        
        # Add scrollbar to treeview
        tree_scroll = ttk.Scrollbar(packet_list_frame, orient=tk.VERTICAL, command=self.packet_tree.yview)
        self.packet_tree.configure(yscrollcommand=tree_scroll.set)
        
        # Pack treeview and scrollbar
        self.packet_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Bind selection event
        self.packet_tree.bind('<<TreeviewSelect>>', self.on_packet_select)
        
        # Packet details frame
        details_frame = ttk.Frame(notebook)
        notebook.add(details_frame, text="Packet Details")
        
        self.details_text = scrolledtext.ScrolledText(details_frame, wrap=tk.WORD, font=('Courier New', 10))
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Packet hex frame
        hex_frame = ttk.Frame(notebook)
        notebook.add(hex_frame, text="Packet Hex")
        
        self.hex_text = scrolledtext.ScrolledText(hex_frame, wrap=tk.WORD, font=('Courier New', 10))
        self.hex_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def start_capture(self):
        if self.is_capturing:
            return
        
        self.is_capturing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.iface_entry.config(state=tk.DISABLED)
        self.filter_entry.config(state=tk.DISABLED)
        
        interface = self.iface_var.get() if self.iface_var.get() else None
        filter_str = self.filter_var.get() if self.filter_var.get() else None
        
        self.status_var.set("Capturing...")
        
        # Start capture in a separate thread
        self.capture_thread = threading.Thread(target=self.capture_packets, args=(interface, filter_str))
        self.capture_thread.daemon = True
        self.capture_thread.start()
    
    def stop_capture(self):
        if not self.is_capturing:
            return
        
        self.is_capturing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.iface_entry.config(state=tk.NORMAL)
        self.filter_entry.config(state=tk.NORMAL)
        
        self.status_var.set("Stopped")
    
    def clear_display(self):
        for item in self.packet_tree.get_children():
            self.packet_tree.delete(item)
        
        self.details_text.delete(1.0, tk.END)
        self.hex_text.delete(1.0, tk.END)
        
        self.packets_captured = 0
        self.packet_count_var.set("0")
        
        for packet_type in self.packet_types:
            self.packet_types[packet_type] = 0
            var_name = f"{packet_type.lower()}_count_var"
            getattr(self, var_name).set("0")
        
        self.packet_data = []
        self.status_var.set("Display cleared")
    
    def capture_packets(self, interface, filter_str):
        try:
            # Use scapy sniff function
            sniff(
                iface=interface,
                filter=filter_str,
                prn=self.process_packet,
                store=False,
                stop_filter=lambda x: not self.is_capturing
            )
        except Exception as e:
            self.status_var.set(f"Error: {str(e)}")
            self.is_capturing = False
            self.root.after(0, self.update_control_states)
    
    def update_control_states(self):
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.iface_entry.config(state=tk.NORMAL)
        self.filter_entry.config(state=tk.NORMAL)
    
    def process_packet(self, packet):
        if not self.is_capturing:
            return
        
        # Increment packet counters
        self.packets_captured += 1
        
        # Extract packet information
        time_stamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        protocol = "Unknown"
        source = "Unknown"
        destination = "Unknown"
        info = ""
        packet_length = len(packet)
        
        # Determine protocol and extract information
        if packet.haslayer(TCP):
            protocol = "TCP"
            self.packet_types['TCP'] += 1
            
            ip_layer = packet.getlayer(IP)
            tcp_layer = packet.getlayer(TCP)
            
            source = f"{ip_layer.src}:{tcp_layer.sport}"
            destination = f"{ip_layer.dst}:{tcp_layer.dport}"
            
            # TCP flags
            flags = []
            if tcp_layer.flags.S:
                flags.append("SYN")
            if tcp_layer.flags.A:
                flags.append("ACK")
            if tcp_layer.flags.F:
                flags.append("FIN")
            if tcp_layer.flags.R:
                flags.append("RST")
            if tcp_layer.flags.P:
                flags.append("PSH")
            if tcp_layer.flags.U:
                flags.append("URG")
            
            flags_str = " ".join(flags) if flags else "None"
            info = f"Seq={tcp_layer.seq} Ack={tcp_layer.ack} Win={tcp_layer.window} Flags={flags_str}"
            
        elif packet.haslayer(UDP):
            protocol = "UDP"
            self.packet_types['UDP'] += 1
            
            ip_layer = packet.getlayer(IP)
            udp_layer = packet.getlayer(UDP)
            
            source = f"{ip_layer.src}:{udp_layer.sport}"
            destination = f"{ip_layer.dst}:{udp_layer.dport}"
            
            info = f"Len={udp_layer.len}"
            
        elif packet.haslayer(ICMP):
            protocol = "ICMP"
            self.packet_types['ICMP'] += 1
            
            ip_layer = packet.getlayer(IP)
            icmp_layer = packet.getlayer(ICMP)
            
            source = ip_layer.src
            destination = ip_layer.dst
            
            # ICMP type
            icmp_type = icmp_layer.type
            icmp_code = icmp_layer.code
            
            type_str = "Echo Request" if icmp_type == 8 else "Echo Reply" if icmp_type == 0 else f"Type={icmp_type}, Code={icmp_code}"
            info = type_str
            
        elif packet.haslayer(ARP):
            protocol = "ARP"
            self.packet_types['ARP'] += 1
            
            arp_layer = packet.getlayer(ARP)
            
            source = arp_layer.psrc
            destination = arp_layer.pdst
            
            # ARP operation
            op_str = "Request" if arp_layer.op == 1 else "Reply" if arp_layer.op == 2 else f"Op={arp_layer.op}"
            info = f"{op_str} {arp_layer.psrc} is-at {arp_layer.hwsrc}"
            
        else:
            protocol = "Other"
            self.packet_types['Other'] += 1
            
            if packet.haslayer(IP):
                ip_layer = packet.getlayer(IP)
                source = ip_layer.src
                destination = ip_layer.dst
                info = f"IP Protocol={ip_layer.proto}"
            elif packet.haslayer(Ether):
                ether_layer = packet.getlayer(Ether)
                source = ether_layer.src
                destination = ether_layer.dst
                info = f"Ethernet Type=0x{ether_layer.type:04x}"
        
        # Store packet data
        packet_data = {
            'packet': packet,
            'time': time_stamp,
            'source': source,
            'destination': destination,
            'protocol': protocol,
            'length': packet_length,
            'info': info
        }
        
        self.packet_data.append(packet_data)
        
        # Update GUI in main thread
        self.root.after(0, self.update_packet_display, packet_data)
    
    def update_packet_display(self, packet_data):
        # Update packet count
        self.packet_count_var.set(str(self.packets_captured))
        
        # Update protocol counts
        for packet_type in self.packet_types:
            var_name = f"{packet_type.lower()}_count_var"
            getattr(self, var_name).set(str(self.packet_types[packet_type]))
        
        # Add packet to treeview
        self.packet_tree.insert('', 'end', values=(
            self.packets_captured,
            packet_data['time'],
            packet_data['source'],
            packet_data['destination'],
            packet_data['protocol'],
            packet_data['length'],
            packet_data['info']
        ))
        
        # Auto-scroll to the bottom if capturing
        if self.is_capturing:
            self.packet_tree.yview_moveto(1.0)
    
    def on_packet_select(self, event):
        selected_items = self.packet_tree.selection()
        if not selected_items:
            return
        
        item = selected_items[0]
        item_index = int(self.packet_tree.item(item, 'values')[0]) - 1
        
        if 0 <= item_index < len(self.packet_data):
            selected_packet = self.packet_data[item_index]['packet']
            self.display_packet_details(selected_packet)
            self.display_packet_hex(selected_packet)
    
    def display_packet_details(self, packet):
        self.details_text.delete(1.0, tk.END)
        
        # Frame information
        if packet.haslayer(Ether):
            ether = packet.getlayer(Ether)
            self.details_text.insert(tk.END, "Ethernet II\n")
            self.details_text.insert(tk.END, f"    Destination: {ether.dst}\n")
            self.details_text.insert(tk.END, f"    Source: {ether.src}\n")
            self.details_text.insert(tk.END, f"    Type: 0x{ether.type:04x}\n")
        
        # IP information
        if packet.haslayer(IP):
            ip = packet.getlayer(IP)
            self.details_text.insert(tk.END, "Internet Protocol Version 4\n")
            self.details_text.insert(tk.END, f"    Version: {ip.version}\n")
            self.details_text.insert(tk.END, f"    Header Length: {ip.ihl * 4} bytes\n")
            self.details_text.insert(tk.END, f"    Total Length: {ip.len}\n")
            self.details_text.insert(tk.END, f"    Identification: 0x{ip.id:04x}\n")
            self.details_text.insert(tk.END, f"    Flags: 0x{ip.flags.value:02x}\n")
            self.details_text.insert(tk.END, f"    Fragment Offset: {ip.frag}\n")
            self.details_text.insert(tk.END, f"    TTL: {ip.ttl}\n")
            self.details_text.insert(tk.END, f"    Protocol: {ip.proto}\n")
            self.details_text.insert(tk.END, f"    Checksum: 0x{ip.chksum:04x}\n")
            self.details_text.insert(tk.END, f"    Source Address: {ip.src}\n")
            self.details_text.insert(tk.END, f"    Destination Address: {ip.dst}\n")
        
        # TCP information
        if packet.haslayer(TCP):
            tcp = packet.getlayer(TCP)
            self.details_text.insert(tk.END, "Transmission Control Protocol\n")
            self.details_text.insert(tk.END, f"    Source Port: {tcp.sport}\n")
            self.details_text.insert(tk.END, f"    Destination Port: {tcp.dport}\n")
            self.details_text.insert(tk.END, f"    Sequence Number: {tcp.seq}\n")
            self.details_text.insert(tk.END, f"    Acknowledgment Number: {tcp.ack}\n")
            self.details_text.insert(tk.END, f"    Header Length: {tcp.dataofs * 4} bytes\n")
            
            # TCP flags
            flags = []
            if tcp.flags.F:
                flags.append("FIN")
            if tcp.flags.S:
                flags.append("SYN")
            if tcp.flags.R:
                flags.append("RST")
            if tcp.flags.P:
                flags.append("PSH")
            if tcp.flags.A:
                flags.append("ACK")
            if tcp.flags.U:
                flags.append("URG")
            if tcp.flags.E:
                flags.append("ECE")
            if tcp.flags.C:
                flags.append("CWR")
            
            self.details_text.insert(tk.END, f"    Flags: {' '.join(flags)}\n")
            self.details_text.insert(tk.END, f"    Window Size: {tcp.window}\n")
            self.details_text.insert(tk.END, f"    Checksum: 0x{tcp.chksum:04x}\n")
            self.details_text.insert(tk.END, f"    Urgent Pointer: {tcp.urgptr}\n")
            
            # TCP options
            if tcp.options:
                self.details_text.insert(tk.END, "    Options:\n")
                for opt_name, opt_value in tcp.options:
                    self.details_text.insert(tk.END, f"        {opt_name}: {opt_value}\n")
        
        # UDP information
        elif packet.haslayer(UDP):
            udp = packet.getlayer(UDP)
            self.details_text.insert(tk.END, "User Datagram Protocol\n")
            self.details_text.insert(tk.END, f"    Source Port: {udp.sport}\n")
            self.details_text.insert(tk.END, f"    Destination Port: {udp.dport}\n")
            self.details_text.insert(tk.END, f"    Length: {udp.len}\n")
            self.details_text.insert(tk.END, f"    Checksum: 0x{udp.chksum:04x}\n")
        
        # ICMP information
        elif packet.haslayer(ICMP):
            icmp = packet.getlayer(ICMP)
            self.details_text.insert(tk.END, "Internet Control Message Protocol\n")
            self.details_text.insert(tk.END, f"    Type: {icmp.type}\n")
            self.details_text.insert(tk.END, f"    Code: {icmp.code}\n")
            self.details_text.insert(tk.END, f"    Checksum: 0x{icmp.chksum:04x}\n")
            self.details_text.insert(tk.END, f"    Identifier: {getattr(icmp, 'id', 'N/A')}\n")
            self.details_text.insert(tk.END, f"    Sequence Number: {getattr(icmp, 'seq', 'N/A')}\n")
        
        # ARP information
        elif packet.haslayer(ARP):
            arp = packet.getlayer(ARP)
            self.details_text.insert(tk.END, "Address Resolution Protocol\n")
            self.details_text.insert(tk.END, f"    Hardware Type: {arp.hwtype}\n")
            self.details_text.insert(tk.END, f"    Protocol Type: 0x{arp.ptype:04x}\n")
            self.details_text.insert(tk.END, f"    Hardware Size: {arp.hwlen}\n")
            self.details_text.insert(tk.END, f"    Protocol Size: {arp.plen}\n")
            self.details_text.insert(tk.END, f"    Operation: {arp.op} ({'Request' if arp.op == 1 else 'Reply' if arp.op == 2 else 'Unknown'})\n")
            self.details_text.insert(tk.END, f"    Sender MAC: {arp.hwsrc}\n")
            self.details_text.insert(tk.END, f"    Sender IP: {arp.psrc}\n")
            self.details_text.insert(tk.END, f"    Target MAC: {arp.hwdst}\n")
            self.details_text.insert(tk.END, f"    Target IP: {arp.pdst}\n")
    
    def display_packet_hex(self, packet):
        self.hex_text.delete(1.0, tk.END)
        
        # Get raw packet data
        raw_data = bytes(packet)
        
        # Format hex dump
        offset = 0
        while offset < len(raw_data):
            # Get current 16-byte chunk
            chunk = raw_data[offset:offset+16]
            
            # Format offset
            hex_offset = f"{offset:04x}"
            
            # Format hex part
            hex_part = ""
            for i, byte in enumerate(chunk):
                if i == 8:  # Add extra space in the middle
                    hex_part += " "
                hex_part += f"{byte:02x} "
            
            # Pad hex part if less than 16 bytes
            hex_part = hex_part.ljust(49)  # 16 bytes * 3 chars each + 1 extra space in the middle
            
            # Format ascii part
            ascii_part = ""
            for byte in chunk:
                if 32 <= byte <= 126:  # Printable ASCII
                    ascii_part += chr(byte)
                else:
                    ascii_part += "."
            
            # Add line to hex dump
            self.hex_text.insert(tk.END, f"{hex_offset}  {hex_part} |{ascii_part}|\n")
            
            offset += 16
    
    def show_about(self):
        messagebox.showinfo(
            "About Network Packet Visualizer",
            "Network Packet Visualizer\n\n"
            "A real-time network packet visualization tool.\n"
            "Captures and displays packet information including TCP, UDP, ICMP, and ARP protocols.\n\n"
            "Requirements: Python 3.x, tkinter, scapy\n\n"
            "Note: This application requires administrator privileges to capture packets."
        )

def main():
    root = tk.Tk()
    app = PacketVisualizer(root)
    root.mainloop()

if __name__ == "__main__":
    main()