import scapy.all as scapy
import logging
import netifaces
import os
import smtplib
import tkinter as tk
import threading
import time
from email.mime.text import MIMEText
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw
from tkinter import messagebox, scrolledtext

# ---------------- CONFIGURATION ----------------
malicious_ips = ["127.0.0.1", "192.168.1.105"]  # List of known bad IPs
suspicious_keywords = ["SELECT", "DROP", "UNION", "OR 1=1", "--", "wget", "curl", "nc -e"]  # SQL Injection & Command Injection
alert_cooldown = {}  # Cooldown dictionary for alerts

LOG_FILE = "ids_log.txt"
logging.basicConfig(filename=LOG_FILE, level=logging.INFO, format="%(asctime)s - %(message)s")

email_alerts_enabled = False  # Set to True to enable email alerts

# ---------------- NETWORK INTERFACE DETECTION ----------------
def get_active_interface():
    """Finds the best active network interface automatically."""
    interfaces = netifaces.interfaces()
    for iface in interfaces:
        addrs = netifaces.ifaddresses(iface)
        if netifaces.AF_INET in addrs:
            return iface
    return "eth0"  # Default fallback

active_iface = get_active_interface()

# ---------------- EMAIL ALERT SYSTEM ----------------
def send_email_alert(alert_msg):
    if not email_alerts_enabled:
        return
    
    sender_email = "your_email@example.com"
    receiver_email = "admin@example.com"
    subject = "🚨 IDS Alert: Suspicious Activity Detected!"
    msg = MIMEText(alert_msg)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        server = smtplib.SMTP("smtp.example.com", 587)
        server.starttls()
        server.login(sender_email, "your_email_password")
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
    except Exception as e:
        print(f"[ERROR] ❌ Failed to send email alert: {e}")

# ---------------- FIREWALL BLOCKING SYSTEM ----------------
def block_ip(ip):
    """Blocks a malicious IP using iptables (Linux only)."""
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")

# ---------------- GUI ALERT SYSTEM ----------------
def show_alert(ip):
    """Displays an alert popup (with cooldown to prevent spam)."""
    current_time = time.time()
    
    if ip not in alert_cooldown or (current_time - alert_cooldown[ip] > 10):
        alert_cooldown[ip] = current_time
        
        def popup():
            root = tk.Tk()
            root.withdraw()  # Hide main window
            messagebox.showwarning("Intrusion Alert", f"[ALERT] 🚨 Malicious IP detected: {ip}")
            root.destroy()

        threading.Thread(target=popup).start()

# ---------------- PACKET ANALYZER ----------------
def packet_callback(packet):
    """Analyzes network packets and detects suspicious activity."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(ICMP) else "Other"

        log_message = f"Packet: {src_ip} → {dst_ip} | Protocol: {protocol}\n"
        gui_log(log_message)

        # 🚨 Detect Malicious IPs
        if src_ip in malicious_ips or dst_ip in malicious_ips:
            alert_msg = f"[ALERT] 🚨 Malicious IP detected: {src_ip} → {dst_ip}"
            gui_log(alert_msg)
            show_alert(src_ip)
            send_email_alert(alert_msg)
            block_ip(src_ip)

        # 🔍 Detect SQL Injection & Command Injection
        if packet.haslayer(Raw):
            payload = packet[Raw].load.decode(errors="ignore")
            for keyword in suspicious_keywords:
                if keyword in payload:
                    alert_msg = f"[ALERT] 🚨 Suspicious Payload Detected ({keyword}) in {src_ip} → {dst_ip}"
                    gui_log(alert_msg)
                    show_alert(src_ip)
                    send_email_alert(alert_msg)
                    break

        # 🚨 Detect Port Scanning (Nmap)
        if packet.haslayer(TCP) and packet[TCP].flags == 2:  # SYN Scan
            alert_msg = f"[ALERT] 🚨 Port Scan Detected from {src_ip}"
            gui_log(alert_msg)
            show_alert(src_ip)
            send_email_alert(alert_msg)

# ---------------- GUI SETUP ----------------
def start_gui():
    global root, log_text
    root = tk.Tk()
    root.title("Intrusion Detection System (IDS)")
    root.geometry("700x400")

    # Stop IDS Button
    stop_button = tk.Button(root, text="Stop IDS", command=stop_sniffing, bg="red", fg="white", font=("Arial", 14))
    stop_button.pack(pady=5)

    # Log Display
    log_text = scrolledtext.ScrolledText(root, height=15, width=80, font=("Arial", 10))
    log_text.pack(pady=5)
    log_text.insert(tk.END, "[INFO] IDS Started...\n")

    root.mainloop()

# ---------------- START SNIFFING ----------------
sniffing_active = True

def gui_log(message):
    """Logs messages to the GUI text box."""
    log_text.insert(tk.END, message + "\n")
    log_text.yview(tk.END)

def start_sniffing():
    """Starts packet sniffing on the detected interface."""
    global sniffing_active
    sniffing_active = True
    threading.Thread(target=sniff_packets, daemon=True).start()

def stop_sniffing():
    """Stops packet sniffing."""
    global sniffing_active
    sniffing_active = False
    gui_log("[INFO] IDS Stopped.")

def sniff_packets():
    """Continuously sniffs packets while IDS is active."""
    while sniffing_active:
        sniff(iface=active_iface, prn=packet_callback, store=0, timeout=5)

# ---------------- START IDS ----------------
threading.Thread(target=start_sniffing, daemon=True).start()
start_gui()
