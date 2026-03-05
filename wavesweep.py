#!/usr/bin/env python3
"""
WaveSweep - Offline Wireless Security Auditor
---------------------------------------------
A Python-based tool for local wireless network analysis and security auditing
"""

import argparse
import json
import os
import time
import sys
from datetime import datetime
from collections import defaultdict
import platform
import subprocess
from typing import Any

# Third-party imports (optional, depending on mode/features)
_MISSING_DEPS = []
try:
    from scapy.all import Dot11, Dot11Beacon, Dot11ProbeReq, Dot11Elt, sniff, RadioTap
except ImportError as e:
    Dot11 = Dot11Beacon = Dot11ProbeReq = Dot11Elt = RadioTap = None
    sniff = None
    _MISSING_DEPS.append(str(e))

try:
    import matplotlib.pyplot as plt
except ImportError as e:
    plt = None
    _MISSING_DEPS.append(str(e))

try:
    from colorama import init, Fore, Style
except ImportError:
    def init(*_args, **_kwargs):
        return None

    class _Plain:
        CYAN = GREEN = BLUE = YELLOW = RED = ""
        RESET_ALL = BRIGHT = ""

    Fore = Style = _Plain()

# Initialize colorama
init(autoreset=True)

# ASCII Art and Branding
WAVESWEEP_ASCII = f"""
{Fore.CYAN}__        __              ____                         
{Fore.CYAN}\\ \\      / /_ ___   _____/ ___|_      _____  ___ _ __  
{Fore.CYAN} \\ \\ /\\ / / _` \\ \\ / / _ \\___ \\ \\ /\\ / / _ \\/ _ \\ '_ \\ 
{Fore.CYAN}  \\ V  V / (_| |\\ V /  __/___) \\ V  V /  __/  __/ |_) |
{Fore.CYAN}   \\_/\\_/ \\__,_| \\_/ \\___|____/ \\_/\\_/ \\___|\\___| .__/ 
{Fore.CYAN}                                                |_|    
{Style.RESET_ALL}{Fore.YELLOW}Offline Wireless Security Auditing Toolkit{Style.RESET_ALL}
"""

# Configuration
if platform.system() == "Windows":
    DEFAULT_INTERFACE = "Wi-Fi"  # Common default, but may vary
    WINDOWS_WARNING = True
else:
    DEFAULT_INTERFACE = "wlan0mon"
    WINDOWS_WARNING = False

SCAN_DURATION = 30  # seconds
BASELINE_FILE = "wavesweep_baseline.json"
REPORT_DIR = "reports"

def get_windows_wifi_info():
    """Get current Wi-Fi connection info on Windows."""
    if platform.system() != "Windows":
        return {}
    try:
        output = subprocess.check_output(
            ['netsh', 'wlan', 'show', 'interfaces'],
            encoding='utf-8'
        )
        info = {}
        for line in output.splitlines():
            if ':' in line:
                key, value = line.split(':', 1)
                info[key.strip()] = value.strip()
        return {
            "SSID": info.get("SSID", ""),
            "BSSID": info.get("BSSID", ""),
            "Interface": info.get("Name", ""),
            "State": info.get("State", ""),
            "Signal": info.get("Signal", ""),
            "Radio type": info.get("Radio type", ""),
            "Authentication": info.get("Authentication", ""),
            "Cipher": info.get("Cipher", ""),
        }
    except Exception:
        return {}

class WaveSweep:
    def __init__(self):
        self.aps: dict[str, dict[str, Any]] = defaultdict(dict)
        self.rogue_aps: dict[str, dict[str, Any]] = {}
        self.vulnerabilities: dict[str, list[str]] = {}
        self.scan_time = None
        self.scan_duration = SCAN_DURATION
        self.baseline = self.load_baseline()
        self.connected_wifi = get_windows_wifi_info() if WINDOWS_WARNING else {}

    def display_banner(self):
        """Show WaveSweep branding"""
        print(WAVESWEEP_ASCII)
        print(f"{Fore.GREEN}[*] Starting WaveSweep at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}[-] Operating in offline mode - No cloud dependencies{Style.RESET_ALL}\n")
        if _MISSING_DEPS:
            print(f"{Fore.YELLOW}[!] Optional dependencies missing: {len(_MISSING_DEPS)} module(s).{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Live capture/visualization features may be limited until dependencies are installed.{Style.RESET_ALL}\n")
        if WINDOWS_WARNING:
            print(f"{Fore.YELLOW}[!] WARNING: Monitor mode is not supported on most Windows systems.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] You may only see packets for the network you are connected to.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] For best results, run on Linux with a compatible Wi-Fi card in monitor mode.{Style.RESET_ALL}\n")
    
    def load_baseline(self):
        """Load AP baseline from file if exists"""
        if os.path.exists(BASELINE_FILE):
            try:
                with open(BASELINE_FILE, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                print(f"{Fore.YELLOW}[!] Corrupted baseline file. Starting fresh.{Style.RESET_ALL}")
        return {}
    
    def save_baseline(self):
        """Save current baseline to file"""
        with open(BASELINE_FILE, 'w') as f:
            json.dump(self.baseline, f, indent=2)
    
    def packet_handler(self, pkt):
        """Process wireless packets"""
        if pkt.haslayer(Dot11Beacon):
            self.process_beacon(pkt)
        elif pkt.haslayer(Dot11ProbeReq):
            self.process_probe_request(pkt)
    
    def process_beacon(self, pkt):
        """Process beacon frames to discover APs"""
        if not pkt.haslayer(Dot11Elt):
            return
            
        bssid = pkt[Dot11].addr2
        try:
            ssid = pkt[Dot11Elt].info.decode(errors='ignore') or "<hidden>"
        except UnicodeDecodeError:
            ssid = "<malformed>"
        
        # Extract capabilities
        capabilities = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}"
                                  "{Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        
        # Get signal strength
        rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
        
        # Get channel from RadioTap layer
        channel = None
        if pkt.haslayer(RadioTap):
            channel = pkt[RadioTap].Channel
        
        # Store AP information
        self.aps[bssid] = {
            "SSID": ssid,
            "BSSID": bssid,
            "Capabilities": capabilities,
            "RSSI": rssi,
            "Channel": channel,
            "LastSeen": time.time(),
            "Type": "AP"
        }
    
    def process_probe_request(self, pkt):
        """Process probe requests to detect clients"""
        if not pkt.haslayer(Dot11Elt):
            return
            
        client = pkt[Dot11].addr2
        try:
            ssid = pkt[Dot11Elt].info.decode(errors='ignore') or "<any>"
        except UnicodeDecodeError:
            ssid = "<malformed>"
        
        # Get signal strength
        rssi = pkt.dBm_AntSignal if hasattr(pkt, 'dBm_AntSignal') else -100
        
        # Store client information
        self.aps[client] = {
            "SSID": ssid,
            "BSSID": client,
            "RSSI": rssi,
            "LastSeen": time.time(),
            "Type": "Client"
        }
    
    def scan_networks(self, interface, duration):
        """Perform wireless scan"""
        if sniff is None:
            raise RuntimeError(
                "scapy is required for live capture. Install dependencies: pip install -r requirements.txt"
            )
        print(f"\n{Fore.CYAN}[*] Scanning on {interface} for {duration} seconds...{Style.RESET_ALL}")
        self.scan_time = datetime.now()
        self.scan_duration = duration
        if WINDOWS_WARNING:
            print(f"{Fore.YELLOW}[!] On Windows, only packets for the connected network may be visible.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Make sure you run this script as Administrator and have Npcap installed.{Style.RESET_ALL}")
        sniff(iface=interface, prn=self.packet_handler, timeout=duration)
        print(f"{Fore.GREEN}[+] Found {len(self.aps)} wireless entities (APs + clients){Style.RESET_ALL}")

    def load_scan_data(self, input_path: str) -> None:
        """Load pre-captured AP/client data from JSON for offline analysis/testing."""
        with open(input_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
        if not isinstance(payload, dict):
            raise ValueError("Input scan JSON must be an object.")
        aps = payload.get("aps", {})
        if not isinstance(aps, dict):
            raise ValueError("Input scan JSON must include an object field `aps`.")
        self.aps = aps
        self.scan_time = datetime.now()
    
    def detect_vulnerabilities(self):
        """Identify security vulnerabilities"""
        weak_ssids = {"default", "linksys", "netgear", "dlink", "xpressset", "belkin", "cisco"}
        self.vulnerabilities = {}
        
        for bssid, ap in self.aps.items():
            if ap["Type"] != "AP":
                continue
                
            issues = []
            ssid = ap["SSID"].lower()
            caps = ap["Capabilities"].lower()
            
            # Weak SSID check
            if any(brand in ssid for brand in weak_ssids):
                issues.append("Default SSID")
                
            # Open network check
            if "privacy" not in caps:
                issues.append("Open Network")
                
            # WEP detection
            if "wep" in caps:
                issues.append("WEP Encryption")
                
            # WPS detection
            if "wps" in caps:
                issues.append("WPS Enabled")
                
            # Enterprise network with weak EAP
            if "802.1x" in caps and "eap" not in caps:
                issues.append("Potential Weak EAP Implementation")
                
            if issues:
                self.vulnerabilities[bssid] = issues
        
        return self.vulnerabilities
    
    def detect_rogues(self):
        """Detect rogue access points"""
        self.rogue_aps = {}
        
        for bssid, ap in self.aps.items():
            if ap["Type"] != "AP":
                continue
                
            # New BSSID not in baseline
            if bssid not in self.baseline:
                self.rogue_aps[bssid] = {
                    "reason": "New BSSID", 
                    "info": ap
                }
                continue
                
            # SSID mismatch
            if self.baseline[bssid]["SSID"] != ap["SSID"]:
                self.rogue_aps[bssid] = {
                    "reason": "SSID mismatch",
                    "baseline": self.baseline[bssid]["SSID"],
                    "current": ap["SSID"]
                }
        
        return self.rogue_aps
    
    def update_baseline(self):
        """Update baseline with persistent APs"""
        for bssid, ap in self.aps.items():
            if ap["Type"] != "AP":
                continue
                
            # Initialize if new
            if bssid not in self.baseline:
                self.baseline[bssid] = {"count": 0, "SSID": ap["SSID"]}
                
            # Update count
            self.baseline[bssid]["count"] += 1
            
            # Promote to trusted if seen enough times
            if self.baseline[bssid]["count"] > 2:
                self.baseline[bssid]["SSID"] = ap["SSID"]
        
        # Remove stale APs
        for bssid in list(self.baseline.keys()):
            if bssid not in self.aps:
                self.baseline[bssid]["count"] -= 1
                if self.baseline[bssid]["count"] < 1:
                    del self.baseline[bssid]
        
        self.save_baseline()
    
    def generate_report(self, format="text"):
        """Generate security report"""
        if not os.path.exists(REPORT_DIR):
            os.makedirs(REPORT_DIR)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"wavesweep_report_{timestamp}"
        
        if format == "text":
            self.generate_text_report(filename)
        elif format == "html":
            self.generate_html_report(filename)
        elif format == "json":
            self.generate_json_report(filename)
        
        print(f"{Fore.GREEN}[+] Report generated: {os.path.join(REPORT_DIR, filename)}.{format}{Style.RESET_ALL}")

    def _security_posture(self) -> dict[str, Any]:
        total_aps = len([ap for ap in self.aps.values() if ap["Type"] == "AP"])
        vuln_aps = len(self.vulnerabilities)
        rogue_count = len(self.rogue_aps)
        penalty = (vuln_aps * 15) + (rogue_count * 20)
        score = max(0, 100 - penalty)
        return {
            "score": score,
            "total_aps": total_aps,
            "vulnerable_aps": vuln_aps,
            "rogue_aps": rogue_count,
            "status": "at_risk" if score < 70 else "acceptable",
        }
    
    def generate_text_report(self, filename):
        """Generate plain text report (no ANSI colors)"""
        report_path = os.path.join(REPORT_DIR, filename + ".txt")

        # ASCII art for "WaveSweep"
        ascii_art = (
            "__        __              ____                             \n"
            "\\ \\      / /_ ___   _____/ ___|_      _____  ___ _ __      \n"
            " \\ \\ /\\ / / _` \\ \\ / / _ \\___ \\ \\ /\\ / / _ \\/ _ \\ '_ \\     \n"
            "  \\ V  V / (_| |\\ V /  __/___) \\ V  V /  __/  __/ |_) |    \n"
            "   \\_/\\_/ \\__,_| \\_/ \\___|____/ \\_/\\_/ \\___|\\___| .__/     \n"
            "                                                |_|        \n"
            "Offline Wireless Security Auditing Toolkit\n"
        )

        with open(report_path, 'w') as f:
            f.write(ascii_art)
            f.write("WaveSweep Security Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Scan Duration: {self.scan_duration} seconds\n")
            posture = self._security_posture()
            f.write(f"Security Score: {posture['score']}/100 ({posture['status']})\n")
            # Add connected Wi-Fi info if available
            if self.connected_wifi:
                f.write("\n=== Connected Wi-Fi Info ===\n")
                for k, v in self.connected_wifi.items():
                    f.write(f"{k}: {v}\n")
            f.write(f"\nAPs Detected: {len([ap for ap in self.aps.values() if ap['Type'] == 'AP'])}\n")
            f.write(f"Clients Detected: {len([ap for ap in self.aps.values() if ap['Type'] == 'Client'])}\n")
            f.write("\n")

            # Vulnerabilities section
            f.write("=== Security Vulnerabilities ===\n")
            if not self.vulnerabilities:
                f.write("No significant vulnerabilities found\n")
            else:
                for bssid, issues in self.vulnerabilities.items():
                    ap = self.aps[bssid]
                    f.write(f"AP: {ap['SSID']} ({bssid})\n")
                    for issue in issues:
                        f.write(f"  - {issue}\n")
                    f.write("\n")

            # Rogue APs section
            f.write("\n=== Rogue AP Detection ===\n")
            if not self.rogue_aps:
                f.write("No rogue APs detected\n")
            else:
                for bssid, info in self.rogue_aps.items():
                    ap = self.aps[bssid]
                    f.write(f"AP: {ap['SSID']} ({bssid})\n")
                    f.write(f"Reason: {info['reason']}\n")
                    if info['reason'] == "SSID mismatch":
                        f.write(f"Baseline SSID: {info['baseline']}\n")
                        f.write(f"Current SSID: {info['current']}\n")
                    f.write("\n")

            # Baseline info
            f.write("\n=== Trusted AP Baseline ===\n")
            f.write(f"{len(self.baseline)} trusted APs in baseline\n")
    
    def generate_html_report(self, filename):
        """Generate HTML report"""
        report_path = os.path.join(REPORT_DIR, filename + ".html")
        
        with open(report_path, 'w') as f:
            f.write("""
            <!DOCTYPE html>
            <html>
            <head>
                <title>WaveSweep Security Report</title>
                <style>
                    body { font-family: Arial, sans-serif; margin: 40px; }
                    h1 { color: #2c3e50; }
                    h2 { color: #3498db; border-bottom: 1px solid #eee; padding-bottom: 5px; }
                    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
                    th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                    th { background-color: #f2f2f2; }
                    tr:nth-child(even) { background-color: #f9f9f9; }
                    .vuln { color: #c0392b; font-weight: bold; }
                    .safe { color: #27ae60; }
                    .summary-card { 
                        background: #f8f9fa; 
                        border-left: 4px solid #3498db;
                        padding: 10px 15px;
                        margin: 15px 0;
                    }
                </style>
            </head>
            <body>
            """)
            
            f.write(f"<h1>WaveSweep Security Report</h1>")
            f.write(f"<p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>")
            f.write(f"<p><strong>Scan Duration:</strong> {self.scan_duration} seconds</p>")
            posture = self._security_posture()
            f.write(f"<p><strong>Security Score:</strong> {posture['score']}/100 ({posture['status']})</p>")
            
            # Summary card
            f.write(f"<div class='summary-card'>")
            f.write(f"<p><strong>APs Detected:</strong> {len([ap for ap in self.aps.values() if ap['Type'] == 'AP'])}</p>")
            f.write(f"<p><strong>Clients Detected:</strong> {len([ap for ap in self.aps.values() if ap['Type'] == 'Client'])}</p>")
            f.write(f"<p><strong>Vulnerable APs:</strong> {len(self.vulnerabilities)}</p>")
            f.write(f"<p><strong>Rogue APs:</strong> {len(self.rogue_aps)}</p>")
            f.write("</div>")
            
            # Vulnerabilities section
            f.write("<h2>Security Vulnerabilities</h2>")
            if not self.vulnerabilities:
                f.write("<p>No significant vulnerabilities found</p>")
            else:
                f.write("<table>")
                f.write("<tr><th>AP (SSID)</th><th>BSSID</th><th>Vulnerabilities</th></tr>")
                for bssid, issues in self.vulnerabilities.items():
                    ap = self.aps[bssid]
                    f.write(f"<tr><td>{ap['SSID']}</td><td>{bssid}</td><td class='vuln'>{', '.join(issues)}</td></tr>")
                f.write("</table>")
            
            # Rogue APs section
            f.write("<h2>Rogue AP Detection</h2>")
            if not self.rogue_aps:
                f.write("<p>No rogue APs detected</p>")
            else:
                f.write("<table>")
                f.write("<tr><th>AP (SSID)</th><th>BSSID</th><th>Reason</th><th>Details</th></tr>")
                for bssid, info in self.rogue_aps.items():
                    ap = self.aps[bssid]
                    details = ""
                    if info['reason'] == "SSID mismatch":
                        details = f"Baseline: {info['baseline']}, Current: {info['current']}"
                    f.write(f"<tr><td>{ap['SSID']}</td><td>{bssid}</td><td>{info['reason']}</td><td>{details}</td></tr>")
                f.write("</table>")
            
            # Baseline info
            f.write("<h2>Trusted AP Baseline</h2>")
            f.write(f"<p>{len(self.baseline)} trusted APs in baseline</p>")
            
            f.write("</body></html>")

    def generate_json_report(self, filename):
        """Generate machine-readable JSON report"""
        report_path = os.path.join(REPORT_DIR, filename + ".json")
        posture = self._security_posture()
        payload = {
            "generated_at": datetime.now().isoformat(timespec="seconds"),
            "scan_duration": self.scan_duration,
            "security_posture": posture,
            "aps": self.aps,
            "vulnerabilities": self.vulnerabilities,
            "rogue_aps": self.rogue_aps,
            "baseline_size": len(self.baseline),
            "connected_wifi": self.connected_wifi,
        }
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2)
    
    def visualize_network(self):
        """Create network visualization"""
        if plt is None:
            print(f"{Fore.YELLOW}[!] matplotlib is required for visualization (pip install matplotlib){Style.RESET_ALL}")
            return
        if not self.aps:
            print(f"{Fore.YELLOW}[!] No data to visualize{Style.RESET_ALL}")
            return
            
        # Prepare data
        ap_data = [ap for ap in self.aps.values() if ap['Type'] == 'AP']
        if not ap_data:
            return
            
        # Create signal strength chart
        plt.figure(figsize=(12, 6))
        
        # Signal strength by AP
        ssids = [ap['SSID'][:15] + (ap['SSID'][15:] and '..') for ap in ap_data]
        rssi_values = [ap['RSSI'] for ap in ap_data]
        
        plt.subplot(1, 2, 1)
        plt.barh(ssids, rssi_values, color='skyblue')
        plt.title('Signal Strength (RSSI)')
        plt.xlabel('dBm')
        plt.grid(axis='x', linestyle='--', alpha=0.7)
        
        # Vulnerability count
        vuln_counts = [len(self.vulnerabilities.get(ap['BSSID'], [])) for ap in ap_data]
        
        plt.subplot(1, 2, 2)
        plt.barh(ssids, vuln_counts, color='salmon')
        plt.title('Vulnerability Count')
        plt.xlabel('Number of Issues')
        plt.grid(axis='x', linestyle='--', alpha=0.7)
        
        plt.tight_layout()
        
        # Save visualization
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        vis_path = os.path.join(REPORT_DIR, f"wavesweep_visualization_{timestamp}.png")
        plt.savefig(vis_path)
        plt.close()
        
        print(f"{Fore.GREEN}[+] Network visualization saved: {vis_path}{Style.RESET_ALL}")
    
    def print_summary(self):
        """Print scan summary to console"""
        print(f"\n{Fore.CYAN}{Style.BRIGHT}=== Scan Summary ==={Style.RESET_ALL}")
        print(f"Scan Time: {self.scan_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Duration: {self.scan_duration} seconds")
        posture = self._security_posture()
        print(f"Security Score: {posture['score']}/100 ({posture['status']})")
        print(f"APs Detected: {len([ap for ap in self.aps.values() if ap['Type'] == 'AP'])}")
        print(f"Clients Detected: {len([ap for ap in self.aps.values() if ap['Type'] == 'Client'])}")
        
        # Vulnerability summary
        vuln_count = len(self.vulnerabilities)
        vuln_color = Fore.RED if vuln_count > 0 else Fore.GREEN
        print(f"\n{vuln_color}Vulnerable APs: {vuln_count}{Style.RESET_ALL}")
        for bssid, issues in self.vulnerabilities.items():
            ap = self.aps[bssid]
            print(f"  - {ap['SSID']} ({ap['BSSID']}): {', '.join(issues)}")
        
        # Rogue AP summary
        rogue_count = len(self.rogue_aps)
        rogue_color = Fore.RED if rogue_count > 0 else Fore.GREEN
        print(f"\n{rogue_color}Rogue APs: {rogue_count}{Style.RESET_ALL}")
        for bssid, info in self.rogue_aps.items():
            ap = self.aps[bssid]
            print(f"  - {ap['SSID']} ({ap['BSSID']}): {info['reason']}")

def main():
    # Parse arguments
    parser = argparse.ArgumentParser(
        description="WaveSweep - Offline Wireless Security Auditor",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("-i", "--interface", default=DEFAULT_INTERFACE,
                        help="Wireless interface in monitor mode")
    parser.add_argument("-d", "--duration", type=int, default=SCAN_DURATION,
                        help="Scan duration in seconds")
    parser.add_argument("-r", "--report", choices=["text", "html", "json"], default="text",
                        help="Report format")
    parser.add_argument("-v", "--visualize", action="store_true",
                        help="Generate network visualization")
    parser.add_argument("-u", "--update-baseline", action="store_true",
                        help="Update AP baseline with current scan")
    parser.add_argument("--input-scan", default=None, help="Optional JSON input with pre-captured AP data.")
    args = parser.parse_args()

    # Initialize WaveSweep
    auditor = WaveSweep()
    auditor.display_banner()

    # Perform scan or load pre-captured data
    if args.input_scan:
        auditor.load_scan_data(args.input_scan)
        print(f"{Fore.GREEN}[+] Loaded input scan data from {args.input_scan}{Style.RESET_ALL}")
    else:
        auditor.scan_networks(args.interface, args.duration)
    
    # Analyze networks
    auditor.detect_vulnerabilities()
    auditor.detect_rogues()
    
    # Update baseline if requested
    if args.update_baseline:
        auditor.update_baseline()
        print(f"{Fore.GREEN}[+] Updated AP baseline{Style.RESET_ALL}")
    
    # Generate reports and visuals
    auditor.generate_report(args.report)
    if args.visualize:
        auditor.visualize_network()
    
    # Print summary
    auditor.print_summary()

if __name__ == "__main__":
    main()
