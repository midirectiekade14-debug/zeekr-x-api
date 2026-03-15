# Zeekr X EV API

Unofficial Python API client and web dashboard for Zeekr electric vehicles. Monitor vehicle status, control charging, climate, locks, and more.

> **Tip:** Create a _separate Zeekr account_ and share the car with it. Otherwise the API will log you out of the phone app.

## Features

- **API Client** — Full vehicle control: status, charging, climate, locks, windows, trunk
- **Dashboard** — Real-time web UI with vehicle status, charging monitor, trip history
- **Configurator** — Visual car configurator with 3D model and color picker
- **Widget** — Compact vehicle status widget for embedding
- **Geofencing** — Create, toggle and manage geofences
- **Sentry Mode** — View sentry events and camera snapshots
- **Trip History** — Trip logs with GPS trackpoints, CSV export
- **Scheduled Actions** — Climate pre-conditioning and charge scheduling

## Quick Start

### 1. Clone

```bash
git clone https://github.com/midirectiekade14-debug/zeekr-x-api.git
cd zeekr-x-api
```

### 2. Install

```bash
# API client only
pip install .

# With dashboard
pip install ".[dashboard]"
```

### 3. Configure

```bash
cp .env.example .env
```

Edit `.env` with your Zeekr credentials:

```
ZEEKR_EMAIL=your-email@example.com
ZEEKR_PASSWORD=your-zeekr-password
ZEEKR_COUNTRY=NL
```

### 4. Run Dashboard

```bash
python dashboard.py
```

Open http://localhost:3941 in your browser. You can change the port with `ZEEKR_PORT=8080`.

## API Usage

```python
from zeekr_ev_api.client import ZeekrClient

client = ZeekrClient(email="you@example.com", password="secret", country="NL")
client.login()

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

| Script | Description |
|--------|-------------|
| `zeekr_status.py` | Detailed vehicle status report |
| `zeekr_control.py` | Lock/unlock, windows, trunk, climate |
| `zeekr_trips.py` | Trip history and statistics |
| `zeekr_fence.py` | Geofence management |
| `zeekr_plans.py` | Charging schedule management |
| `verify_sig.py` | API signature verification tool |

## Dashboard Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /` | Main dashboard |
| `GET /widget` | Compact status widget |
| `GET /configurator` | Visual car configurator |
| `GET /api/vehicles` | List vehicles |
| `GET /api/trips` | Trip history |
| `GET /api/trips/csv` | Export trips as CSV |
| `GET /api/fences` | List geofences |
| `GET /api/sentry/events` | Sentry mode events |
| `GET /api/charge-plan` | Charging schedule |
| `GET /api/schedules` | All scheduled actions |

## API Keys

All required signing keys (HMAC, RSA, AES) are **included** in `src/zeekr_ev_api/const.py`. You don't need to extract anything to get started — just add your email and password.

### Updating keys after a Zeekr app update

When Zeekr releases a new app version, the signing keys may change. Use the included extraction tool to get the new keys:

```bash
# Download the latest Zeekr APK from your phone or APKMirror
# Then run:
python tools/extract_keys.py path/to/zeekr.apk
```

The tool scans the APK's DEX files and native libraries (`.so`) for:

| Key | Location in APK | Used for |
|-----|----------------|----------|
| HMAC Access Key | `libHttpSecretKey.so` | Pre-login API authentication |
| HMAC Secret Key | `libAppSecret.so` | Pre-login request signing |
| RSA Public Key | DEX (`classes*.dex`) | Password encryption (OAEP) |
| PROD Signing Key | DEX (`SignInterceptor`) | Post-login X-SIGNATURE header |
| VIN AES Key + IV | `libcrypto-util.so` | Vehicle ID encryption |

The tool outputs the values in copy-paste format for `const.py`.

### How to get the APK

1. **From your phone:** Use [APK Extractor](https://play.google.com/store/apps/details?id=com.ext.ui) or `adb pull`
2. **From APKMirror:** Search for "Zeekr" on [apkmirror.com](https://www.apkmirror.com/)
3. **XAPK format** is also supported — the tool handles nested APKs automatically

## Security Notes

- **Never commit your `.env` file** — it contains your credentials
- The dashboard uses session-based auth with rate limiting
- The signing keys in `const.py` are app-level (same for all users, extracted from the public APK) — they are not personal credentials

## Requirements

- Python 3.10+
- `pycryptodome` (encryption)
- `requests` (HTTP)
- `fastapi` + `uvicorn` + `python-dotenv` (dashboard, optional)

## Credits

Based on [Fryyyyy/zeekr_ev_api](https://github.com/Fryyyyy/zeekr_ev_api). Extended with dashboard, vehicle control tools, trip tracking, geofencing, sentry mode, and scheduled actions.

## License

MIT
