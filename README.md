# Hidden Camera Detector

A local privacy tool that scans the Wi-Fi network you're connected to for devices that look like hidden cameras or microphones — inspired by the method of listing every device on the router and flagging CCTV manufacturers or devices sending data outbound.

## What it does

1. Discovers devices on your local network (IP + MAC).
2. Looks up the manufacturer from the MAC address (OUI).
3. Flags known camera brands (Hikvision, Dahua, Amcrest, Reolink, Wyze, Tapo, Ring, Arlo, Eufy, etc.).
4. Optionally scans common camera ports (RTSP 554, HTTP 80/8080, ONVIF, etc.).
5. Assigns a simple risk level and suggests next steps.
6. Includes the classic flashlight lens-glint check for cases where the network isolates guests (most hotels).

**This is a helper, not a guarantee.** It only sees devices on the same Wi-Fi network you joined. SD-card-only cameras, wired cameras on a different network, or cameras that never join the guest Wi-Fi will not appear. Always do a physical sweep.

## Run on your phone

### Android (recommended — Termux)
1. Install [Termux](https://f-droid.org/packages/com.termux/) from F-Droid (not Play Store).
2. Open Termux and run:
   ```bash
   pkg update && pkg install python git
   git clone https://github.com/paappraiser/hidden-camera-detector.git
   cd hidden-camera-detector
   pip install -r requirements.txt
   python app.py
   ```
3. Open the browser on your phone to `http://127.0.0.1:5000`.
4. Connect to the room Wi-Fi **before** starting the scan.

### iOS
iOS is more restricted. Options:
- Use a laptop/desktop instead, or
- Run it on a computer and access the page from your phone on the same Wi-Fi (change `app.run(host="0.0.0.0")` and note the computer’s IP).

**Note:** Network scanning on mobile may be limited by the OS. The flashlight check works everywhere.

## Setup (run this on the computer/phone that is connected to the room's Wi-Fi)

```bash
# Clone or download this folder, then:
cd hidden-camera-detector
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

**Note:** ARP scanning often needs administrator/root privileges.

```bash
# Linux / macOS
sudo python app.py

# Windows (run Command Prompt or PowerShell as Administrator)
python app.py
```

Then open http://127.0.0.1:5000 in your browser.

## How to use in an Airbnb / hotel

1. Connect your phone or laptop to the room Wi-Fi.
2. Run the app (as above).
3. Click **Scan Network**.
4. Review any high-risk devices. Do **not** touch the device.
5. If nothing is flagged, or the network keeps guests isolated, do the flashlight check:
   - Turn all lights off.
   - Slowly sweep your phone flashlight across smoke detectors, clocks, chargers, air vents, and anything facing the bed.
   - Look for a small bright glint from a lens.
6. If you find something, leave the room, contact the host and the platform (Airbnb/Booking), and consider local authorities. Do not unplug or move it (evidence).

## Limitations

- Requires being on the same network as the camera.
- Many hotel networks isolate guests, so you may see only your own device → use the flashlight method.
- Randomized MAC addresses (common on phones) may show as "Unknown".
- Not a substitute for professional equipment or legal advice.
- Use responsibly and only on networks you are authorized to scan.

## Inspired by

The approach shared by @0xGoldTooth of using an AI coding assistant to list every device on the local Wi-Fi and flag anything that looks like a CCTV camera.
