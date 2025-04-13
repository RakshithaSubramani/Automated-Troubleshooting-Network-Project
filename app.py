import pandas as pd
import threading
import re
from flask import Flask, render_template, request, jsonify
from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
import time
import pytz
import os
from collections import Counter

app = Flask(__name__)

# Network interface
INTERFACE = r"\Device\NPF_{2BA22351-5BA9-4A5B-8F00-8CDE427DFFD8}"
packet_data = []  # Store packet data
lock = threading.Lock()  # Thread safety
capture_active = False  # Track capture state

# Responses dictionary with \nSolution: on a new line
responses = {
    # Greeting
    r"hi|hello|hey|greetings|what'?s up|good day|hey there": 
        lambda stats: f"Hi! I’m NetBot, ready to analyze your network (last captured at {stats.get('latest_time', 'unknown')}). Ask about 'latency,' 'protocols,' or 'status' for real-time insights!\nSolution: Try asking about specific network issues.",
    
    # Latency
    r"^(high|excessive|check|what|my|test|report).*?(latency|delay|lag|ping|response time)$|^(latency|delay|lag|ping).*$|.*(latency|delay|lag|ping).*(issue|problem|high|check|status|fix|test|report)": 
        lambda stats: f"Latency check: max delay is {stats.get('max_delta_time', 0):.6f}s, avg {stats.get('avg_delta_time', 0):.6f}s across {stats.get('total_packets', 0)} packets. Latency is {'HIGH' if stats.get('max_delta_time', 0) > 0.1 else 'LOW'}.\nSolution: Restart your router, use a wired connection, or contact your ISP to reduce delays.",
    
    # Packet Loss
    r"^(what|check|my|test).*?(packet loss|dropped packets|data loss|lost packets|packet drop)$|^(packet loss|data loss).*$|.*(packet loss|data loss|dropped packets|lost packets).*(issue|problem|check|fix|status|test)": 
        lambda stats: f"Packet loss check: {stats.get('total_bytes', 0)} bytes transferred over {stats.get('total_packets', 0)} packets.\nSolution: Check cables, update router firmware, or enable QoS to stabilize connections.",
    r"fix.*(packet loss|dropped packets|data loss|lost packets)|how.*(fix|resolve|deal with|repair|reduce).*?(packet loss|data loss)": 
        lambda stats: f"To fix packet loss ({stats.get('total_packets', 0)} packets captured).\nSolution: Restart your router, avoid Wi-Fi interference (e.g., change channel), or contact your ISP.",
    
    # Large Packets
    r"^(what|check|my|test).*?(big packet|large packet|oversized packet|jumbo packet)$|^(big|large|oversized).*(packet).*$|.*(packet).*(size|big|large|oversized).*(issue|problem|check|status|test)": 
        lambda stats: f"Largest packet: {stats.get('max_packet_length', 0)} bytes.\nSolution: Lower MTU (e.g., 1500) in router settings or optimize large file transfers to reduce fragmentation.",
    
    # Network Slowness
    r"^(why|is|my|the|check|test).*?(network|connection|internet|link|bandwidth|speed).*(slow|lag|laggy|poor|bad|delay|unresponsive|performance issues)$|^(slow|lag|poor).*(network|connection|internet|link).*$|.*(network|connection|internet|link).*(slow|lag|laggy|poor|bad|delay|unresponsive|performance).*(issue|problem|check|status|test)": 
        lambda stats: f"Slowness detected: avg delay {stats.get('avg_delta_time', 0):.6f}s, max packet {stats.get('max_packet_length', 0)} bytes from {stats.get('unique_sources', 0)} sources.\nSolution: Reduce connected devices, restart modem, or run a speed test.",
    
    # QoS
    r"^(what|how|check|test).*?(qos|quality of service|traffic priority|bandwidth management)$|^(qos).*$|.*(qos|quality of service|traffic priority).*(issue|problem|check|manage|status|test)": 
        lambda stats: f"QoS check: {stats.get('total_packets', 0)} packets, common protocol: {stats.get('protocol_counts', {}).get('TCP', 'None')}.\nSolution: Enable QoS in your router to prioritize critical apps (e.g., video calls).",
    
    # Router Restart
    r"restart.*(router|modem|gateway)|reboot.*(network|connection|device)|fix.*(router|modem)|^(router|modem).*(issue|problem|restart|check|status|fix)$|.*(router|modem).*(issue|problem|restart|check|status|fix)": 
        lambda stats: f"Router check: {stats.get('total_bytes', 0)} bytes captured at {stats.get('latest_time', 'unknown')}.\nSolution: Unplug router for 30 seconds, reconnect, and wait 2 minutes to stabilize.",
    
    # Network Check
    r"check.*(network|connection|status|performance|health|activity)|status.*(network|internet|connection)|^(network|connection|internet).*(status|check|issue|problem|health)$|.*(network|connection|internet).*(status|check|issue|problem|health|activity)": 
        lambda stats: f"Network status: {stats.get('total_packets', 0)} packets, max packet {stats.get('max_packet_length', 0)} bytes, total traffic {stats.get('total_bytes', 0)} bytes, {stats.get('tcp_packets', 0)} TCP, {stats.get('tls_packets', 0)} TLS packets from {stats.get('unique_sources', 0)} sources to {stats.get('unique_destinations', 0)} destinations.\nSolution: If unstable, check router logs or recapture packets.",
    
    # Protocol Info
    r"^(what|check|test).*?(protocol|traffic type|data protocol)$|^(protocol).*$|.*(protocol|traffic type).*(used|details|issue|check|status|test)": 
        lambda stats: f"Protocols: {', '.join([f'{k} ({v} packets)' for k, v in stats.get('protocol_counts', {}).items()])}.\nSolution: Ensure firewall allows key protocols like TCP ({stats.get('tcp_packets', 0)} packets).",
    
    # Data Usage
    r"how much.*(data|traffic|bandwidth)|data.*(amount|usage|total|consumption|check|status)|^(data|traffic).*(issue|problem|check|status)$|.*(data|traffic).*(amount|usage|total|consumption|issue|problem|check|status)": 
        lambda stats: f"Data usage: {stats.get('total_bytes', 0)} bytes over {stats.get('total_packets', 0)} packets.\nSolution: Monitor bandwidth via router settings to avoid throttling.",
    
    # Source/Destination
    r"^(who|what|check|test).*?(source|destination|ip|address|traffic from|traffic to).*$|.*(source|destination|ip|address).*(check|status|who|where)": 
        lambda stats: f"Traffic involves {stats.get('unique_sources', 0)} sources and {stats.get('unique_destinations', 0)} destinations.\nSolution: Verify IPs in your firewall to block unwanted traffic.",
    
    # Packet Info
    r"^(what|check|test).*?(info|packet info|details|summary)$|^(info|details).*$|.*(info|packet info|details|summary).*(check|status)": 
        lambda stats: f"Common packet info: '{stats.get('common_info', 'No info')}' across {stats.get('total_packets', 0)} packets.\nSolution: Review packet details in Wireshark for anomalies or contact your admin.",
    
    # Time Info
    r"^(what|check|when|test).*?(time|timestamp|utc|local time|capture time)$|^(time|utc).*$|.*(time|timestamp|utc|local time).*(check|status|when)": 
        lambda stats: f"Last capture: local time {stats.get('latest_time', 'unknown')}, UTC {stats.get('latest_utc_time', 'unknown')}.\nSolution: Ensure system clock is synced (e.g., 'w32tm /resync') for accurate logs.",
    
    # Help
    r"help|assist|support|what.*can.*do|guide|troubleshoot|assistance": 
        lambda stats: f"I can check your network ({stats.get('total_bytes', 0)} bytes, {stats.get('total_packets', 0)} packets). Ask about 'latency,' 'source,' or 'status' for tailored solutions!\nSolution: Try specific queries like 'check latency' or 'network status'.",
    
    # Network Failure
    r"^(network|connection|internet|link).*(fail|down|broken|no|lost|disconnected|offline|unavailable)$|^(fail|down|broken).*(network|connection|internet|link).*$|.*(network|connection|internet|link).*(fail|down|broken|no|lost|disconnected|offline|unavailable).*(issue|problem|check|status)": 
        lambda stats: f"Network failure: max delay {stats.get('max_delta_time', 0):.6f}s from {stats.get('unique_sources', 0)} sources.\nSolution: Reset adapter ('ipconfig /renew'), try DNS 8.8.8.8, or check ISP status.",
    
    # High CPU/Memory
    r"^(high|excessive|check|test).*?(cpu|memory|ram|usage|load|resource)$|^(high|excessive).*(cpu|memory|ram|usage|load).*$|.*(cpu|memory|ram|usage|load|resource).*(issue|problem|check|status|test|high|excessive)": 
        lambda stats: f"High usage may impact network ({stats.get('total_bytes', 0)} bytes).\nSolution: End heavy processes in Task Manager or restart your PC.",
    
    # Authentication Failure
    r"^(auth|authentication|login|sign-in).*(fail|error|issue|problem|denied)$|^(fail|error).*(login|auth|authentication).*$|.*(auth|authentication|login|sign-in).*(fail|error|issue|problem|denied|check|status)": 
        lambda stats: f"Login issue; network active with {stats.get('total_packets', 0)} packets.\nSolution: Reset password, check account policies, or verify server IPs ({stats.get('unique_destinations', 0)} destinations).",
    
    # Low Disk Space
    r"^(disk|storage|space).*(low|full|running out|insufficient)$|^(low|full).*(space|disk|storage).*$|.*(disk|storage|space).*(low|full|running out|insufficient|issue|problem|check|status)|not.*enough.*(space|storage)": 
        lambda stats: f"Low disk space; network captured at {stats.get('latest_time', 'unknown')}.\nSolution: Clear temp files ('del /q %temp%\*'), empty Recycle Bin, or use external storage.",
    
    # Service/Application Crash
    r"^(service|app|application|program|software).*(crash|freeze|fail|down|hang|error)$|^(crash|fail|freeze).*(service|app|application|program).*$|.*(service|app|application|program|software).*(crash|freeze|fail|down|hang|error).*(issue|problem|check|status)": 
        lambda stats: f"App crash; network shows {stats.get('total_packets', 0)} packets.\nSolution: Update the app, check logs, or restart service (e.g., 'systemctl restart nginx').",
    
    # Clock Sync
    r"^(clock|time).*(sync|desync|wrong|off|misaligned)$|^(sync|desync).*(clock|time).*$|.*(clock|time).*(sync|desync|wrong|off|misaligned|issue|problem|check|status)": 
        lambda stats: f"Clock issue; last capture at {stats.get('latest_utc_time', 'unknown')}.\nSolution: Sync time with 'w32tm /resync' or set NTP to 'pool.ntp.org'.",
    
    # Blue Screen/Kernel Panic
    r"^(blue screen|kernel panic|crash screen|system crash|bsod).*$|^(crash|panic).*(screen|system).*$|.*(blue screen|kernel panic|crash screen|system crash|bsod).*(issue|problem|check|status)": 
        lambda stats: f"System crash; network active at {stats.get('latest_time', 'unknown')}.\nSolution: Boot in Safe Mode, update drivers, or check Event Viewer.",
    
    # Database Timeout
    r"^(db|database).*(timeout|slow|unresponsive|hang)$|^(timeout|slow).*(db|database).*$|.*(db|database).*(timeout|slow|unresponsive|hang|issue|problem|check|status)": 
        lambda stats: f"DB timeout; avg latency {stats.get('avg_delta_time', 0):.6f}s to {stats.get('unique_destinations', 0)} destinations.\nSolution: Restart DB service, optimize queries, or check server IPs.",
    
    # SSL Certificate Expiry
    r"^(ssl|certificate|cert).*(expir|due|renew|out of date|expired)$|^(expir|renew).*(ssl|certificate|cert).*$|.*(ssl|certificate|cert).*(expir|due|renew|out of date|expired|issue|problem|check|status)": 
        lambda stats: f"SSL issue affects {stats.get('tls_packets', 0)} TLS packets.\nSolution: Renew via Let’s Encrypt or check certificate validity.",
    
    # Backup Failure
    r"^(backup|restore).*(fail|error|problem|unsuccessful)$|^(fail|error).*(backup|restore).*$|.*(backup|restore).*(fail|error|problem|unsuccessful|issue|check|status)": 
        lambda stats: f"Backup failure; network captured {stats.get('total_bytes', 0)} bytes.\nSolution: Check storage space, review logs, or reschedule backup.",
    
    # Configuration Drift
    r"^(config|configuration|firewall|settings).*(drift|change|altered|deviation)$|^(drift|change).*(config|configuration|firewall).*$|.*(config|configuration|firewall|settings).*(drift|change|altered|deviation|issue|problem|check|status)": 
        lambda stats: f"Config drift; {stats.get('tcp_packets', 0)} TCP packets detected.\nSolution: Restore settings from backup or use config management tools.",
    
    # Unresponsive Server/VM
    r"^(server|vm|virtual machine|host).*(unresponsive|down|frozen|hang|offline)$|^(unresponsive|down).*(server|vm|virtual machine).*$|.*(server|vm|virtual machine|host).*(unresponsive|down|frozen|hang|offline|issue|problem|check|status)": 
        lambda stats: f"Server down; traffic to {stats.get('unique_destinations', 0)} destinations.\nSolution: Ping server, restart VM, or check resource usage.",
    
    # Port/Service Not Listening
    r"^(port|service).*(not.*listen|unavailable|down|blocked|closed)$|^(not.*listen|unavailable).*(port|service).*$|.*(port|service).*(not.*listen|unavailable|down|blocked|closed|issue|problem|check|status)": 
        lambda stats: f"Service issue; {stats.get('tcp_packets', 0)} TCP packets.\nSolution: Check ports with 'netstat -tuln', restart service, or update firewall.",
    
    # Rogue Process/Malware
    r"^(rogue|unknown|malicious|virus|malware).*(process|program|software|threat)$|^(rogue|virus).*(process|program).*$|.*(rogue|unknown|malicious|virus|malware).*(process|program|software|threat|detected|issue|check|status)": 
        lambda stats: f"Malware alert; {stats.get('total_bytes', 0)} bytes from {stats.get('unique_sources', 0)} sources.\nSolution: Run antivirus, kill processes via Task Manager, and isolate device.",
    
    # Email Failure
    r"^(email|mail).*(fail|delivery|stuck|error|bounce)$|^(fail|stuck).*(email|mail).*$|.*(email|mail).*(fail|delivery|stuck|error|bounce|issue|problem|check|status)|can'?t.*send.*(email|mail)": 
        lambda stats: f"Email issue; {stats.get('total_packets', 0)} packets captured.\nSolution: Check SMTP settings, clear queue, or verify server status.",
    
    # Website Down
    r"^(website|site|page|web).*(down|unavailable|not working|offline|error)$|^(down|unavailable).*(website|site|page).*$|.*(website|site|page|web).*(down|unavailable|not working|offline|error|issue|problem|check|status)": 
        lambda stats: f"Website down; {stats.get('tcp_packets', 0)} TCP packets to {stats.get('unique_destinations', 0)} destinations.\nSolution: Restart web server (e.g., 'sudo systemctl restart apache2'), check DNS, or restore backup.",
    
    # Unauthorized Login/Brute Force
    r"^(unauthor|brute force|hack|attack).*(login|access|attempt|entry)$|^(unauthor|brute).*(login|access).*$|.*(unauthor|brute force|hack|attack).*(login|access|attempt|entry|issue|problem|check|status)": 
        lambda stats: f"Unauthorized access; {stats.get('unique_sources', 0)} sources detected.\nSolution: Block IPs via firewall (e.g., 'iptables -A INPUT -s IP -j DROP'), enable 2FA, or check logs.",
    
    # Software Update Failure
    r"^(software|update|patch).*(fail|error|stuck|unsuccessful)$|^(fail|stuck).*(update|software).*$|.*(software|update|patch).*(fail|error|stuck|unsuccessful|issue|problem|check|status)": 
        lambda stats: f"Update failed; {stats.get('total_bytes', 0)} bytes transferred.\nSolution: Clear update cache (e.g., 'sudo apt-get clean'), check internet, or reinstall.",
    
    # API Rate Limit
    r"^(api|request).*(rate limit|exceed|throttle|over limit)$|^(rate limit|exceed).*(api|request).*$|.*(api|request).*(rate limit|exceed|throttle|over limit|issue|problem|check|status)|too many.*requests": 
        lambda stats: f"API limit hit; {stats.get('total_packets', 0)} packets.\nSolution: Reduce requests, use backoff, or contact API provider.",
    
    # Fallback
    r".*": 
        lambda stats: f"Sorry, I didn’t get that. Network shows {stats.get('total_bytes', 0)} bytes at {stats.get('latest_time', 'unknown')}.\nSolution: Try 'check status,' 'latency,' or 'source' for details."
}

def process_packet(packet):
    """Process a single packet and extract detailed information."""
    if IP in packet:
        try:
            with lock:
                timestamp = datetime.now(pytz.UTC)
                abs_time = time.time()
                protocol = "UNKNOWN"
                info = "No info"
                if TCP in packet:
                    protocol = "TCP"
                    if packet[TCP].dport == 443 or packet[TCP].sport == 443:
                        info = "TLS"
                elif UDP in packet:
                    protocol = "UDP"
                else:
                    protocol = str(packet[IP].proto)

                packet_info = {
                    "delta time": None,  # Computed later
                    "length": len(packet),
                    "abs_time": abs_time,
                    "cumulative bytes": None,  # Computed later
                    "source": packet[IP].src,
                    "destination": packet[IP].dst,
                    "protocol": protocol,
                    "info": info,
                    "time": timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    "utc_time": timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
                }
                packet_data.append(packet_info)
        except Exception as e:
            print(f"Error processing packet: {e}")

def capture_packets():
    """Start packet capture in a loop."""
    global capture_active
    try:
        print(f"Starting capture on {INTERFACE}...")
        capture_active = True
        sniff(iface=INTERFACE, prn=process_packet, store=False, timeout=20)
    except Exception as e:
        print(f"Capture error: {e}")
    finally:
        capture_active = False

def save_to_csv():
    """Save packet data to CSV with computed fields."""
    with lock:
        if not packet_data:
            return None
        df = pd.DataFrame(packet_data)
        if not df.empty:
            start_time = df["abs_time"].min()
            df["delta time"] = df["abs_time"] - start_time
            df["cumulative bytes"] = df["length"].cumsum()
            df.fillna({"length": 0, "protocol": "UNKNOWN", "source": "UNKNOWN", "destination": "UNKNOWN", "info": "No info"}, inplace=True)
            df["length"] = df["length"].astype(int)
            df["delta time"] = df["delta time"].astype(float)
            df["cumulative bytes"] = df["cumulative bytes"].astype(int)
            try:
                csv_path = "network_features.csv"
                df.to_csv(csv_path, index=False)
                print(f"Saved {len(df)} packets to {csv_path}")
                return df
            except Exception as e:
                print(f"Error saving CSV: {e}")
                return None
        return None

def compute_stats(df):
    """Compute statistics for responses."""
    if df is None or df.empty:
        return {
            "total_packets": 0,
            "total_bytes": 0,
            "max_packet_length": 0,
            "max_delta_time": 0,
            "avg_delta_time": 0,
            "protocol_counts": {},
            "unique_sources": 0,
            "unique_destinations": 0,
            "tcp_packets": 0,
            "tls_packets": 0,
            "latest_time": "unknown",
            "latest_utc_time": "unknown",
            "common_info": "No info"
        }
    protocols = df["protocol"].value_counts().to_dict()
    infos = df["info"].value_counts().to_dict()
    return {
        "total_packets": len(df),
        "total_bytes": df["length"].sum(),
        "max_packet_length": df["length"].max(),
        "max_delta_time": df["delta time"].max(),
        "avg_delta_time": df["delta time"].mean(),
        "protocol_counts": protocols,
        "unique_sources": len(df["source"].unique()),
        "unique_destinations": len(df["destination"].unique()),
        "tcp_packets": protocols.get("TCP", 0),
        "tls_packets": infos.get("TLS", 0),
        "latest_time": df["time"].iloc[-1] if not df["time"].empty else "unknown",
        "latest_utc_time": df["utc_time"].iloc[-1] if not df["utc_time"].empty else "unknown",
        "common_info": max(infos, key=infos.get, default="No info")
    }

def get_response(user_input, stats):
    """Match user input to response using regex."""
    for pattern, response_func in responses.items():
        if re.search(pattern, user_input, re.IGNORECASE):
            return response_func(stats)
    return responses[r".*"](stats)  # Fallback

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/ask", methods=["POST"])
def ask():
    global capture_active
    try:
        user_input = request.form.get("message", "").strip()
        # Start capture if not running
        if not capture_active:
            capture_thread = threading.Thread(target=capture_packets)
            capture_thread.daemon = True
            capture_thread.start()
            time.sleep(1)  # Allow capture to start

        # Save and compute stats
        df = save_to_csv()
        stats = compute_stats(df)
        response = get_response(user_input, stats)
        return jsonify({"reply": response})
    except Exception as e:
        return jsonify({"reply": f"Error: {str(e)}"})

if __name__ == "__main__":
    app.run(debug=True)