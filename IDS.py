import scapy.all as scapy
import logging
import netifaces
import os  # Fixing missing os module import
import smtplib
from email.mime.text import MIMEText
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# ---------------- CONFIGURATION ----------------
malicious_ips = ["127.0.0.1", "192.168.1.105"]  # Add more known bad IPs
suspicious_keywords = ["SELECT", "DROP", "UNION", "OR 1=1", "--", "wget", "curl", "nc -e"]  # SQL Injection & Command Injection

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
    return "eth0"  # Default fallback if no active interface is found

active_iface = get_active_interface()
print(f"[INFO] 🚀 IDS Running on Interface: {active_iface}")

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
        server = smtplib.SMTP("smtp.example.com", 587)  # Update with actual SMTP server
        server.starttls()
        server.login(sender_email, "your_email_password")
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        print("[INFO] 📧 Email alert sent successfully!")
    except Exception as e:
        print(f"[ERROR] ❌ Failed to send email alert: {e}")

# ---------------- FIREWALL BLOCKING SYSTEM ----------------
def block_ip(ip):
    """Blocks a malicious IP using iptables."""
    print(f"[ACTION] 🔥 Blocking Malicious IP: {ip}")
    logging.warning(f"[ACTION] IP Blocked: {ip}")
    os.system(f"sudo iptables -A INPUT -s {ip} -j DROP")  # Fix: os module added

# ---------------- PACKET ANALYZER ----------------
def packet_callback(packet):
    """Analyzes network packets and detects suspicious activity."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "ICMP" if packet.haslayer(ICMP) else "Other"

        # Print captured packet for debugging
        print(f"[DEBUG] Packet: {src_ip} → {dst_ip} | Protocol: {protocol}")

        # 🚨 Detect Malicious IPs
        if src_ip in malicious_ips or dst_ip in malicious_ips:
            alert_msg = f"[ALERT] 🚨 Malicious IP detected: {src_ip} → {dst_ip}"
            print(alert_msg)
            logging.warning(alert_msg)
            send_email_alert(alert_msg)
            block_ip(src_ip)

        # 🔍 Detect SQL Injection & Command Injection
        if packet.haslayer(Raw):  
            payload = packet[Raw].load.decode(errors="ignore")
            for keyword in suspicious_keywords:
                if keyword in payload:
                    alert_msg = f"[ALERT] 🚨 Suspicious Payload Detected ({keyword}) in {src_ip} → {dst_ip}"
                    print(alert_msg)
                    logging.warning(alert_msg)
                    send_email_alert(alert_msg)
                    break

        # 🚨 Detect Port Scanning (Nmap)
        if packet.haslayer(TCP) and packet[TCP].flags == 2:
            alert_msg = f"[ALERT] 🚨 Port Scan Detected from {src_ip}"
            print(alert_msg)
            logging.warning(alert_msg)
            send_email_alert(alert_msg)

# ---------------- START SNIFFING ----------------
def start_sniffing():
    """Starts packet sniffing on the detected interface."""
    print(f"[INFO] 🛡️ IDS is running on {active_iface}...")
    sniff(iface=active_iface, prn=packet_callback, store=0)  # No filter, captures all traffic

# Run IDS
start_sniffing()

