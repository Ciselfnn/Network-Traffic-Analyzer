
import scapy.all as scapy
from scapy.layers import http
import time
from datetime import datetime # Library baru untuk format waktu

# --- Konfigurasi Deteksi Anomali & Logging ---
syn_tracker = {}
SYN_THRESHOLD = 20
TIME_WINDOW = 5
LOG_FILE = "security_alerts.log" # Nama file untuk menyimpan log

def log_alert(message):
    """Fungsi untuk menyimpan peringatan ke dalam file log"""
    # Mengambil waktu saat ini (contoh: 2026-05-03 14:30:00)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Membuka file dengan mode "a" (append/tambahkan), 
    # agar log lama tidak tertimpa log baru
    with open(LOG_FILE, "a") as file:
        file.write(f"[{timestamp}] {message}\n")

def sniff(interface):
    print(f"[*] Memulai Network Traffic Analyzer di interface: {interface}")
    print(f"[*] File Log Aktif: {LOG_FILE}")
    print("[*] Menunggu paket data...\n" + "="*60)
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def detect_syn_scan(packet, ip_src):
    if packet.haslayer(scapy.TCP) and packet[scapy.TCP].flags == 'S':
        current_time = time.time()

        if ip_src not in syn_tracker:
            syn_tracker[ip_src] = {'count': 1, 'first_seen': current_time}
        else:
            if current_time - syn_tracker[ip_src]['first_seen'] <= TIME_WINDOW:
                syn_tracker[ip_src]['count'] += 1
                
                if syn_tracker[ip_src]['count'] == SYN_THRESHOLD:
                    # Buat pesan peringatan
                    alert_msg = f"ANCAMAN DETEKSI: TCP SYN Scan dari IP {ip_src}"
                    
                    # Tampilkan di layar terminal
                    print(f"\n[!!!] PERINGATAN KEAMANAN [!!!]")
                    print(alert_msg + "\n" + "="*60)
                    
                    # Simpan ke dalam file log
                    log_alert(alert_msg)
            else:
                syn_tracker[ip_src] = {'count': 1, 'first_seen': current_time}

def process_packet(packet):
    if packet.haslayer(scapy.IP):
        ip_src = packet[scapy.IP].src
        ip_dst = packet[scapy.IP].dst
        protocol = packet[scapy.IP].proto
        
        proto_name = "Lainnya"
        if protocol == 1: proto_name = "ICMP"
        elif protocol == 6: proto_name = "TCP"
        elif protocol == 17: proto_name = "UDP"

        print(f"[IP] {ip_src} -> {ip_dst} | Protokol: {proto_name}")
        detect_syn_scan(packet, ip_src)

    if packet.haslayer(http.HTTPRequest):
        try:
            url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
            print(f"[HTTP] Meminta URL: {url}")
            
            if packet.haslayer(scapy.Raw):
                load = packet[scapy.Raw].load.decode(errors='ignore')
                keywords = ["username", "user", "password", "pass", "login"]
                for keyword in keywords:
                    if keyword in load.lower():
                        alert_msg = f"DATA SENSITIF TERETAS (HTTP): Kemungkinan kredensial bocor dari {packet[scapy.IP].src}"
                        print(f"\n[!!!] {alert_msg}\n")
                        log_alert(alert_msg) # Simpan juga kebocoran password ke log
                        break
        except Exception:
            pass 

if __name__ == "__main__":
    target_interface = "eth0" # Menggunakan 'any' agar lebih mudah diuji
    
    try:
        sniff(target_interface)
    except KeyboardInterrupt:
        print("\n[*] Menutup Network Traffic Analyzer...")
    except PermissionError:
        print("\n[!] Error: Anda harus menjalankan skrip ini sebagai root (gunakan sudo).")
