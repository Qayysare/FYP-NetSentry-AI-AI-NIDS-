import threading
from datetime import datetime
from scapy.all import IP, TCP, conf, sniff, wrpcap
from database import database_cursor

PCAP_OUTPUT_PATH = "captured_threats.pcap"
flask_app = None  # Global variable to store Flask app context


def save_threat_to_db(ip_src, ip_dst, port_dst, attack_type, severity):
    """Inserts real-time PCAP alert into the MySQL database using Flask app context"""
    if flask_app is None:
        print("[!] Cannot log to DB: Flask app instance not passed to sniffer.")
        return

    try:
        with flask_app.app_context():
            with database_cursor() as (conn, cursor):
                query = """
                    INSERT INTO threats (attack_type, source_ip, destination_ip, severity, status, detected_at)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """
                dest_formatted = f"{ip_dst}:{port_dst}"
                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                cursor.execute(
                    query,
                    (
                        attack_type,
                        ip_src,
                        dest_formatted,
                        severity,
                        "Active",
                        now,
                    ),
                )
                conn.commit()
    except Exception as e:
        print(f"[!] Database log error: {e}")

def handle_packet(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        if tcp_layer.flags == "S":
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            dst_port = tcp_layer.dport

            print(
                f"[NIDS ALERT] TCP SYN Event: {src_ip}:{tcp_layer.sport} -> {dst_ip}:{dst_port}"
            )

            # Save packet file
            wrpcap(PCAP_OUTPUT_PATH, packet, append=True)

            # Insert alert to DB
            save_threat_to_db(
                ip_src=src_ip,
                ip_dst=dst_ip,
                port_dst=dst_port,
                attack_type="SYN Scan",
                severity="Medium",
            )


def start_background_sniffer(app=None, interface=None):
    global flask_app
    if app is not None:
        flask_app = app  # Assign app instance to global variable

    target_iface = interface if interface else conf.iface
    print(f"[*] Starting PCAP Traffic Sniffer on interface: {target_iface}")

    sniffer_thread = threading.Thread(
        target=sniff,
        kwargs={
            "iface": target_iface,
            "prn": handle_packet,
            "filter": "ip",
            "store": 0,
        },
        daemon=True,
    )
    sniffer_thread.start()