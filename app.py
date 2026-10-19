#!/usr/bin/env python3
"""
Hidden Camera Detector — local network scanner for privacy checks
in Airbnbs, hotels, and rentals.

Inspired by the method of listing every device on the Wi-Fi and
flagging CCTV manufacturers or suspicious outbound behavior.
"""

import socket
import ipaddress
import concurrent.futures
from typing import List, Dict, Optional
from flask import Flask, render_template_string, jsonify, request
from scapy.all import ARP, Ether, srp, conf
from mac_vendor_lookup import MacLookup

app = Flask(__name__)
mac_lookup = MacLookup()
# Uncomment the next line once if you want a fresh vendor database
# mac_lookup.update_vendors()

# Known camera / surveillance related keywords and brands
CAMERA_KEYWORDS = [
    "hikvision", "dahua", "amcrest", "reolink", "wyze", "tapo", "ring",
    "arlo", "eufy", "xiaomi", "yi technology", "axis", "uniview", "unv",
    "foscam", "lorex", "swann", "vivotek", "hanwha", "samsung techwin",
    "avigilon", "bosch security", "geovision", "milesight", "instar",
    "ipcamera", "ipcam", "cctv", "nvr", "dvr", "camera", "cam ", "ipc",
    "onvif", "rtsp"
]

# Common camera-related ports
CAMERA_PORTS = [80, 443, 554, 8000, 8080, 8554, 9000, 37777, 34567, 9527, 2020, 8899]

RISK_CRITICAL = "CRITICAL"
RISK_HIGH = "HIGH"
RISK_MEDIUM = "MEDIUM"
RISK_LOW = "LOW"
RISK_INFO = "INFO"


def get_local_subnet() -> str:
    """Return the local /24 subnet as a string, e.g. '192.168.1.0/24'."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
        return str(network)
    except Exception:
        return "192.168.1.0/24"


def arp_scan(target: str, timeout: int = 3) -> List[Dict]:
    """Perform an ARP scan and return list of {'ip': , 'mac': }."""
    try:
        conf.verb = 0
        packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
        answered, _ = srp(packet, timeout=timeout, verbose=0)
        devices = []
        for sent, received in answered:
            devices.append({
                "ip": received.psrc,
                "mac": received.hwsrc.upper()
            })
        return devices
    except Exception as e:
        print(f"ARP scan error: {e}")
        return []


def lookup_vendor(mac: str) -> str:
    try:
        return mac_lookup.lookup(mac)
    except Exception:
        return "Unknown"


def is_camera_vendor(vendor: str) -> bool:
    if not vendor:
        return False
    v = vendor.lower()
    return any(kw in v for kw in CAMERA_KEYWORDS)


def scan_port(ip: str, port: int, timeout: float = 0.4) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except Exception:
        return False


def scan_ports(ip: str, ports: List[int]) -> List[int]:
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(scan_port, ip, p): p for p in ports}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                if future.result():
                    open_ports.append(port)
            except Exception:
                pass
    return sorted(open_ports)


def classify_device(device: Dict) -> Dict:
    vendor = device.get("vendor", "")
    open_ports = device.get("open_ports", [])
    camera_vendor = is_camera_vendor(vendor)
    has_rtsp = 554 in open_ports
    has_web = any(p in open_ports for p in [80, 443, 8080])
    has_onvif_like = any(p in open_ports for p in [8000, 37777, 34567])

    if camera_vendor and has_rtsp:
        risk = RISK_CRITICAL
        reason = "Known camera manufacturer + RTSP port open"
    elif camera_vendor:
        risk = RISK_HIGH
        reason = "Known camera / surveillance manufacturer"
    elif has_rtsp:
        risk = RISK_HIGH
        reason = "RTSP streaming port (554) open"
    elif has_onvif_like or (has_web and any(kw in vendor.lower() for kw in ["unknown", "private"])):
        risk = RISK_MEDIUM
        reason = "Suspicious ports open on unidentified device"
    else:
        risk = RISK_LOW
        reason = "No strong camera indicators"

    device["risk"] = risk
    device["reason"] = reason
    device["camera_vendor"] = camera_vendor
    return device


HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Hidden Camera Detector</title>
<style>
  :root { --bg: #0f1115; --card: #1a1d24; --accent: #ff4d4d; --ok: #3dd68c; --warn: #ffb84d; --text: #e8eaed; --muted: #9aa0a6; }
  * { box-sizing: border-box; }
  body { font-family: system-ui, -apple-system, sans-serif; background: var(--bg); color: var(--text); margin: 0; padding: 20px; }
  h1 { margin: 0 0 8px; font-size: 1.6rem; }
  .subtitle { color: var(--muted); margin-bottom: 24px; }
  button { background: var(--accent); color: white; border: none; padding: 12px 24px; border-radius: 8px; font-size: 1rem; cursor: pointer; }
  button:disabled { opacity: 0.6; cursor: not-allowed; }
  .card { background: var(--card); border-radius: 12px; padding: 16px; margin: 12px 0; }
  .risk-CRITICAL { border-left: 4px solid #ff2a2a; }
  .risk-HIGH { border-left: 4px solid var(--accent); }
  .risk-MEDIUM { border-left: 4px solid var(--warn); }
  .risk-LOW { border-left: 4px solid var(--ok); }
  .risk-INFO { border-left: 4px solid #5c7cfa; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 999px; font-size: 0.75rem; font-weight: 600; }
  .badge-CRITICAL, .badge-HIGH { background: #ff2a2a33; color: #ff6b6b; }
  .badge-MEDIUM { background: #ffb84d33; color: #ffb84d; }
  .badge-LOW { background: #3dd68c33; color: #3dd68c; }
  pre { background: #111; padding: 12px; border-radius: 8px; overflow-x: auto; font-size: 0.85rem; }
  .section { margin-top: 32px; }
  .flashlight { background: #1e2a1e; border: 1px solid #3dd68c55; }
</style>
</head>
<body>
  <h1>Hidden Camera Detector</h1>
  <p class="subtitle">Scan the Wi-Fi you're on for devices that look like cameras. Inspired by listing every router client and flagging CCTV brands.</p>

  <button id="scanBtn" onclick="startScan()">Scan Network</button>
  <span id="status" style="margin-left:12px; color:var(--muted);"></span>

  <div id="results"></div>

  <div class="section">
    <div class="card flashlight">
      <h2>Flashlight Lens Check (always do this)</h2>
      <p>Network isolation is common in hotels. If the scan shows little or nothing suspicious:</p>
      <ol>
        <li>Turn off all lights in the room.</li>
        <li>Slowly move your phone flashlight across smoke detectors, clocks, chargers, air vents, picture frames, and anything facing the bed or seating area.</li>
        <li>Watch for a small, bright glint — a camera lens reflects light differently than ordinary surfaces.</li>
        <li>Check twice. Move slowly.</li>
      </ol>
    </div>
  </div>

  <div class="section">
    <div class="card">
      <h2>AI Prompt (from the original post)</h2>
      <p>Paste this into Claude Code / an AI coding assistant while connected to the room Wi-Fi:</p>
      <pre>I'm a guest on this Wi-Fi, a hotel room or a rental, not my own place. Help me check the room is private. Look only at the network I'm on, and only list what's there. Don't log in to anything and don't open any video.

List every device you can see: what kind it is, who makes it, and whether it keeps sending data to somewhere outside the building. Point out anything that looks like a camera or a microphone, tell me how sure you are, and roughly where in the room it probably is.

If you find something, tell me not to touch it and help me write a message to the host and to support. If the network keeps guests apart and you can't see other devices, say so, and walk me through the flashlight check: lights off, phone torch slowly across smoke detectors, clocks, chargers and anything facing the bed, watching for a lens glint.</pre>
    </div>
  </div>

  <div class="section">
    <p style="color:var(--muted); font-size:0.85rem;">
      Disclaimer: This tool only sees devices on the same network. It is not a guarantee of privacy. 
      Do not tamper with any device you find. Contact the host and platform if something looks wrong.
      Use only on networks you are authorized to scan.
    </p>
  </div>

<script>
async function startScan() {
  const btn = document.getElementById('scanBtn');
  const status = document.getElementById('status');
  const results = document.getElementById('results');
  btn.disabled = true;
  status.textContent = 'Scanning… this can take 10–30 seconds';
  results.innerHTML = '';

  try {
    const res = await fetch('/scan', { method: 'POST' });
    const data = await res.json();
    status.textContent = `Found ${data.devices.length} devices on ${data.subnet}`;
    renderResults(data);
  } catch (e) {
    status.textContent = 'Scan failed: ' + e.message;
  } finally {
    btn.disabled = false;
  }
}

function renderResults(data) {
  const container = document.getElementById('results');
  if (!data.devices.length) {
    container.innerHTML = '<div class="card">No devices found. The network may be isolating clients. Do the flashlight check.</div>';
    return;
  }

  // Sort by risk
  const order = {CRITICAL:0, HIGH:1, MEDIUM:2, LOW:3, INFO:4};
  data.devices.sort((a,b) => (order[a.risk]||9) - (order[b.risk]||9));

  let html = '';
  for (const d of data.devices) {
    const ports = d.open_ports && d.open_ports.length ? d.open_ports.join(', ') : 'none scanned or none open';
    html += `
      <div class="card risk-${d.risk}">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <strong>${d.ip}</strong>
          <span class="badge badge-${d.risk}">${d.risk}</span>
        </div>
        <div style="color:var(--muted); font-size:0.9rem; margin:4px 0;">
          MAC: ${d.mac}<br>
          Vendor: ${d.vendor || 'Unknown'}
        </div>
        <div>${d.reason}</div>
        <div style="font-size:0.85rem; color:var(--muted); margin-top:6px;">Open ports: ${ports}</div>
      </div>`;
  }
  container.innerHTML = html;
}
</script>
</body>
</html>
"""


@app.route("/")
def index():
    return render_template_string(HTML)


@app.route("/scan", methods=["POST"])
def scan():
    subnet = get_local_subnet()
    raw_devices = arp_scan(subnet)

    results = []
    for d in raw_devices:
        vendor = lookup_vendor(d["mac"])
        device = {
            "ip": d["ip"],
            "mac": d["mac"],
            "vendor": vendor,
            "open_ports": []
        }
        # Port scan only if it looks interesting or always (limited ports)
        if is_camera_vendor(vendor) or True:  # always scan a few key ports
            device["open_ports"] = scan_ports(d["ip"], CAMERA_PORTS)
        results.append(classify_device(device))

    return jsonify({
        "subnet": subnet,
        "devices": results
    })


if __name__ == "__main__":
    print("Starting Hidden Camera Detector…")
    print("Open http://127.0.0.1:5000 in your browser")
    print("Note: ARP scanning may require administrator/root privileges.")
    app.run(host="0.0.0.0", port=5000, debug=False)
