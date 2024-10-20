from scapy.all import sniff, IP, TCP, UDP, Raw


def process_packet(packet):
   
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        protocol = packet[IP].proto
        
        print(f"\n[+] Packet: {ip_src} -> {ip_dst} | Protocol: {protocol}")
        
       
        if TCP in packet:
            tcp_src_port = packet[TCP].sport
            tcp_dst_port = packet[TCP].dport
            print(f"    TCP: {tcp_src_port} -> {tcp_dst_port}")
        
        
        elif UDP in packet:
            udp_src_port = packet[UDP].sport
            udp_dst_port = packet[UDP].dport
            print(f"    UDP: {udp_src_port} -> {udp_dst_port}")
        
        
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            print(f"    Payload: {payload[:50]}...") 


def start_sniffing(interface="eth0"):
    print(f"[*] Starting packet sniffing on {interface}...")
    sniff(iface=interface, prn=process_packet, store=False)

if __name__ == "__main__":
    interface = "eth0"  
    start_sniffing(interface)


