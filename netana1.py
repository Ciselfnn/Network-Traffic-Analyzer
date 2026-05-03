import scapy.all as scapy
import time
import argparse
import sys

# --- Konfigurasi Warna ANSI ---
C_CYAN = '\033[96m'
C_GREEN = '\033[92m'
C_YELLOW = '\033[93m'
C_BLUE = '\033[94m'
C_MAGENTA = '\033[95m'
C_WHITE = '\033[97m'
C_RESET = '\033[0m'

# --- Variabel Statistik Global ---
start_time = 0
total_packets = 0
total_bytes = 0
endpoints = set()
protocols = {}
talkers = {}

def format_bytes(size):
    """Mengubah ukuran bytes menjadi format yang mudah dibaca (KB, MB)"""
    if size < 1024: return f"{size:.1f} B"
    elif size < 1024 * 1024: return f"{size/1024:.1f} KB"
    else: return f"{size/(1024*1024):.1f} MB"

def process_packet(packet):
    global start_time, total_packets, total_bytes
    
    if start_time == 0:
        start_time = time.time()
        
    size = len(packet)
    total_packets += 1
    total_bytes += size
    
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        proto = packet[scapy.IP].proto
        
        endpoints.add(ip_src)
        endpoints.add(ip_dst)
        
        # Identifikasi Protokol Dasar
        proto_name = "OTHER"
        if proto == 1: proto_name = "ICMP"
        elif proto == 6: proto_name = "TCP"
        elif proto == 17: proto_name = "UDP"
        
        # Update Statistik Protokol
        if proto_name not in protocols:
            protocols[proto_name] = {'pkts': 0, 'bytes': 0}
        protocols[proto_name]['pkts'] += 1
        protocols[proto_name]['bytes'] += size
        
        # Update Statistik "Top Talkers"
        if ip_src not in talkers: talkers[ip_src] = {'sent_pkts':0, 'recv_pkts':0, 'sent_bytes':0, 'recv_bytes':0}
        if ip_dst not in talkers: talkers[ip_dst] = {'sent_pkts':0, 'recv_pkts':0, 'sent_bytes':0, 'recv_bytes':0}
        
        talkers[ip_src]['sent_pkts'] += 1
        talkers[ip_src]['sent_bytes'] += size
        talkers[ip_dst]['recv_pkts'] += 1
        talkers[ip_dst]['recv_bytes'] += size
        
        # Ambil Port jika TCP/UDP
        src_port, dst_port = "", ""
        if packet.haslayer(scapy.TCP):
            src_port, dst_port = str(packet[scapy.TCP].sport), str(packet[scapy.TCP].dport)
        elif packet.haslayer(scapy.UDP):
            src_port, dst_port = str(packet[scapy.UDP].sport), str(packet[scapy.UDP].dport)
            
        # Format Baris Live Output (Menyesuaikan gambar)
        if src_port and dst_port:
            port_str = f":{C_CYAN}{src_port:<5}{C_RESET} -> :{C_CYAN}{dst_port:<5}{C_RESET}"
        else:
            port_str = "               " # Padding jika tidak ada port
            
        print(f"{C_CYAN}{proto_name:<5}{C_RESET} {C_GREEN}{ip_src:<15}{C_RESET} -> {C_GREEN}{ip_dst:<15}{C_RESET} {port_str} \t {C_CYAN}{size:>4}{C_RESET} bytes")

def print_summary():
    """Mencetak tabel ringkasan saat program dihentikan"""
    end_time = time.time()
    duration = end_time - start_time if start_time > 0 else 0
    bandwidth = (total_bytes / duration) if duration > 0 else 0
    
    # 1. Summary Box
    print(f"\n{C_GREEN}────────────────────────────── Capture Summary ──────────────────────────────{C_RESET}")
    print(f"Duration: {duration:.1f}s")
    print(f"Total Packets: {total_packets}")
    print(f"Total Bytes: {format_bytes(total_bytes)}")
    print(f"Average Bandwidth: {format_bytes(bandwidth)}/s")
    print(f"Unique Endpoints: {len(endpoints)}")
    print(f"Protocols Seen: {len(protocols)}")
    print(f"{C_GREEN}─────────────────────────────────────────────────────────────────────────────{C_RESET}\n")
    
    if total_packets == 0:
        return

    # 2. Protocol Distribution Table
    print(f"               {C_WHITE}Protocol Distribution{C_RESET}")
    print("┌──────────┬─────────┬──────────┬────────────┐")
    print("│ Protocol │ Packets │ Bytes    │ Percentage │")
    print("├──────────┼─────────┼──────────┼────────────┤")
    for p, stats in protocols.items():
        pct = (stats['pkts'] / total_packets) * 100
        print(f"│ {C_CYAN}{p:<8}{C_RESET} │ {C_GREEN}{stats['pkts']:>7}{C_RESET} │ {C_YELLOW}{format_bytes(stats['bytes']):>8}{C_RESET} │ {C_MAGENTA}{pct:>9.1f}%{C_RESET} │")
    print("└──────────┴─────────┴──────────┴────────────┘\n")
    
    # 3. Top Talkers Table
    print(f"                               {C_WHITE}Top 10 Talkers{C_RESET}")
    print("┌─────────────────┬──────────────┬──────────────┬─────────────┬─────────────┬─────────────┐")
    print("│ IP Address      │ Packets Sent │ Packets Recv │ Bytes Sent  │ Bytes Recv  │ Total       │")
    print("├─────────────────┼──────────────┼──────────────┼─────────────┼─────────────┼─────────────┤")
    
    # Sorting IP berdasarkan total bytes yang dikirim & diterima
    sorted_talkers = sorted(talkers.items(), key=lambda x: x[1]['sent_bytes'] + x[1]['recv_bytes'], reverse=True)[:10]
    
    for ip, s in sorted_talkers:
        total_b = s['sent_bytes'] + s['recv_bytes']
        print(f"│ {C_CYAN}{ip:<15}{C_RESET} │ {C_GREEN}{s['sent_pkts']:>12}{C_RESET} │ {C_YELLOW}{s['recv_pkts']:>12}{C_RESET} │ {C_BLUE}{format_bytes(s['sent_bytes']):>11}{C_RESET} │ {C_MAGENTA}{format_bytes(s['recv_bytes']):>11}{C_RESET} │ {C_WHITE}{format_bytes(total_b):>11}{C_RESET} │")
    print("└─────────────────┴──────────────┴──────────────┴─────────────┴─────────────┴─────────────┘")

if __name__ == "__main__":
    # Konfigurasi Argumen (Agar mirip pemakaian di gambar)
    parser = argparse.ArgumentParser(description="Advanced Network Traffic Analyzer")
    parser.add_argument("-i", "--interface", default="eth0", help="Interface jaringan (contoh: eth0, lo)")
    parser.add_argument("-c", "--count", type=int, default=0, help="Jumlah batas paket (0 = tanpa henti)")
    args = parser.parse_args()

    print(f"{C_CYAN}Starting capture on {args.interface}...{C_RESET}")
    print("Press Ctrl+C to stop\n")
    
    try:
        # Sniffing dimulai sesuai argumen yang diketik user
        scapy.sniff(iface=args.interface, count=args.count, store=False, prn=process_packet)
        # Akan memanggil print_summary otomatis jika batas -c tercapai
        print_summary()
    except KeyboardInterrupt:
        # Akan memanggil print_summary jika user menekan Ctrl+C
        print_summary()
    except Exception as e:
        print(f"\n[!] Error: {e}. Pastikan Anda menggunakan sudo!")
