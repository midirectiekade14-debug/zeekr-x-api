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

## Security Notes

- **Never commit your `.env` file** — it contains your credentials
- The dashboard uses session-based auth with rate limiting
- API keys (HMAC, RSA, AES) must be extracted from the Zeekr APK — they are not included in this repo

## Requirements

- Python 3.10+
- `pycryptodome` (encryption)
- `requests` (HTTP)
- `fastapi` + `uvicorn` + `python-dotenv` (dashboard, optional)

## Credits

Based on [Fryyyyy/zeekr_ev_api](https://github.com/Fryyyyy/zeekr_ev_api). Extended with dashboard, vehicle control tools, trip tracking, geofencing, sentry mode, and scheduled actions.

## License

MIT
