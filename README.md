# Zeekr EV Dashboard & API

Control and monitor your Zeekr electric vehicle from your browser. See battery level, range, location, charging status, lock/unlock doors, control climate, and much more.

![Dashboard](https://img.shields.io/badge/dashboard-web--based-blue) ![Python](https://img.shields.io/badge/python-3.10+-green) ![License](https://img.shields.io/badge/license-MIT-lightgrey)

> **Important:** Create a _separate Zeekr account_ and share the car with it. Otherwise using this API will log you out of the official phone app.

---

## What Can It Do?

- **Live Dashboard** — Battery %, range, location, charging status in your browser
- **Vehicle Control** — Lock/unlock, windows, trunk, climate (start heating/cooling remotely)
- **Charging Management** — Set charge limits, schedules, and travel plans
- **Trip History** — View past trips with GPS routes, export to CSV
- **Geofencing** — Get notified when your car enters/leaves an area

---

## Installation (Step by Step)

### What You Need

- A computer (Windows, Mac, or Linux)
- Python 3.10 or newer ([download here](https://www.python.org/downloads/))
- An Android phone with the Zeekr app installed
- A USB cable to connect your phone to your computer

### Step 1: Download This Project

Click the green **"Code"** button at the top of this page, then **"Download ZIP"**.
Unzip the folder somewhere on your computer (e.g., your Desktop).

Or if you know git:
```bash
git clone https://github.com/midirectiekade14-debug/zeekr-x-api.git
cd zeekr-x-api
```

### Step 2: Install Python Dependencies

Open a terminal/command prompt in the project folder and run:

```bash
pip install ".[dashboard]"
```

### Step 3: Get Your Login Token

The Zeekr API requires a login token from your phone. This sounds complicated, but we've made it easy with an included tool.

#### Option A: Automatic Capture (Recommended)

You need **ADB** (Android Debug Bridge) installed on your computer:
- **Windows:** Download [Android Platform Tools](https://developer.android.com/tools/releases/platform-tools), unzip, and add to your PATH
- **Mac:** `brew install android-platform-tools`
- **Linux:** `sudo apt install adb`

Then:

1. **Enable USB Debugging** on your phone:
   - Go to Settings → About Phone → tap "Build Number" 7 times
   - Go back to Settings → Developer Options → enable "USB Debugging"

2. **Connect your phone** via USB and allow the debugging prompt

3. **Run the capture tool:**
   ```bash
   python tools/capture_token.py --email your-email@example.com
   ```

4. **Log in on your phone** when the app opens. The tool will capture your token automatically.

5. A `session.json` file will be created — that's all the dashboard needs!

#### Option B: Manual (Logcat Only)

If you're already logged into the Zeekr app:

```bash
python tools/capture_token.py --logcat-only
```

This reads the existing app logs without restarting the app.

### Step 4: Start the Dashboard

```bash
python dashboard.py
```

Open **http://localhost:3941** in your browser. Done! 🎉

You can change the port: `ZEEKR_PORT=8080 python dashboard.py`

---

## How Authentication Works

### EU Users
The European Zeekr app (`com.zeekr.overseas`) uses a direct Bearer token login via `eu-snc-tsp-api-gw.zeekrlife.com`. No HMAC signing is needed for pre-login. The `capture_token.py` tool handles this automatically.

### SEA / Middle East / Latin America Users
These regions use HMAC-signed requests for the initial authentication. The required signing keys are already included in `src/zeekr_ev_api/const.py` (extracted from the APK — they're the same for all users).

If Zeekr releases a new app version and the keys stop working, you can extract new ones:

```bash
# Get the latest APK from your phone or apkmirror.com
python tools/extract_keys.py path/to/zeekr.apk
```

Or use [Wysie's zeekr_key_extractor](https://github.com/Wysie/zeekr_key_extractor) for advanced extraction from `libenv.so`.

---

## Token Refresh

Your Bearer token is valid for about **7 days**. The refresh token lasts **30 days**.

When the token expires, simply run `capture_token.py` again, or the dashboard will prompt you to re-authenticate.

---

## API Usage (For Developers)

```python
from zeekr_ev_api.client import ZeekrClient

# Load from session.json
import json
with open("session.json") as f:
    session = json.load(f)

client = ZeekrClient(session_data=session)

# Get vehicle status
status = client.get_vehicle_status()
print(f"Battery: {status['soc']}%")
print(f"Range: {status['remaining_range']} km")

# Lock the car
client.lock_vehicle()

# Start climate
client.start_climate(temperature=21)
```

## CLI Tools

| Script | What It Does |
|--------|-------------|
| `zeekr_status.py` | Shows detailed vehicle status |
| `zeekr_control.py` | Lock/unlock, windows, trunk, climate |
| `zeekr_trips.py` | Trip history and statistics |
| `zeekr_fence.py` | Geofence management |
| `zeekr_plans.py` | Charging schedule management |

## Dashboard API Endpoints

| URL | What It Returns |
|-----|----------------|
| `GET /` | Main dashboard page |
| `GET /widget` | Compact status widget (for embedding) |
| `GET /api/vehicles` | List of your vehicles |
| `GET /api/status` | Current vehicle status |
| `GET /api/trips` | Trip history |
| `GET /api/trips/csv` | Export trips as CSV file |
| `GET /api/fences` | Your geofences |
| `GET /api/charge-plan` | Charging schedule |

---

## Included Signing Keys

All API signing keys (HMAC, RSA, AES) are **included** in `src/zeekr_ev_api/const.py`. These are app-level keys extracted from the public APK — they are the same for every user and are **not** personal credentials.

| Key | Source | Purpose |
|-----|--------|---------|
| HMAC Access Key | `libenv.so` (OLLVM-encrypted) | API gateway authentication (SEA/EM) |
| HMAC Secret Key | `libenv.so` (OLLVM-encrypted) | Request signing (SEA/EM) |
| RSA Public Key | DEX bytecode | Password encryption |
| PROD Signing Key | `SignInterceptor` class | Post-login X-SIGNATURE header |
| VIN AES Key + IV | `libcrypto-util.so` | Vehicle ID encryption |

---

## Security

- **Never share your `session.json`** — it contains your personal login tokens
- **Never commit `.env` or `session.json`** to git (both are in `.gitignore`)
- The dashboard uses session cookies with rate limiting

## Requirements

- Python 3.10+
- Android phone with Zeekr app (for token capture)
- ADB (Android Debug Bridge) for the capture tool

## Credits

Based on [Fryyyyy/zeekr_ev_api](https://github.com/Fryyyyy/zeekr_ev_api). Extended with dashboard, vehicle control, trip tracking, geofencing, scheduled actions, EU authentication support, and ADB token capture tool.

Key extraction powered by [Wysie/zeekr_key_extractor](https://github.com/Wysie/zeekr_key_extractor).

## License

MIT
