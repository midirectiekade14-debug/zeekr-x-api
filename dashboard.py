#!/usr/bin/env python3
"""Zeekr EV Dashboard — FastAPI web app op poort 3941."""

import json
import logging
import os
import secrets
import sys
import threading
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from io import StringIO
from typing import Any, Dict, List, Optional
import csv

import uvicorn
from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware


# ── Security: Rate Limiter ────────────────────────────────────────────────────

class RateLimitState:
    def __init__(self):
        self.attempts: Dict[str, List[float]] = defaultdict(list)

    def is_limited(self, key: str, max_attempts: int, window_sec: int) -> bool:
        now = time.time()
        self.attempts[key] = [t for t in self.attempts[key] if now - t < window_sec]
        if len(self.attempts[key]) >= max_attempts:
            return True
        self.attempts[key].append(now)
        return False

_rate_limiter = RateLimitState()


# ── Security: CSRF + CSP + Rate Limit Middleware ──────────────────────────────

SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}

class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # CSRF: check Origin header on state-changing requests
        if request.method not in SAFE_METHODS and request.url.path.startswith("/api/"):
            origin = request.headers.get("origin", "")
            host = request.headers.get("host", "")
            if origin:
                from urllib.parse import urlparse
                parsed = urlparse(origin)
                origin_host = parsed.netloc.split(":")[0] if parsed.netloc else ""
                request_host = host.split(":")[0] if host else ""
                if origin_host and request_host and origin_host != request_host:
                    return JSONResponse(status_code=403, content={"error": "Verzoek geweigerd"})

        # Rate limit: login endpoint
        if request.url.path == "/api/login" and request.method == "POST":
            client_ip = request.client.host if request.client else "unknown"
            if _rate_limiter.is_limited(f"login:{client_ip}", max_attempts=5, window_sec=60):
                return JSONResponse(status_code=429, content={"error": "Te veel inlogpogingen. Probeer het over een minuut opnieuw."})

        # Rate limit: control endpoints
        if request.url.path.startswith("/api/control/") and request.method == "POST":
            client_ip = request.client.host if request.client else "unknown"
            if _rate_limiter.is_limited(f"control:{client_ip}", max_attempts=20, window_sec=60):
                return JSONResponse(status_code=429, content={"error": "Te veel commando's. Even wachten."})

        response = await call_next(request)

        # CSP header
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://unpkg.com; "
            "style-src 'self' 'unsafe-inline' https://unpkg.com; "
            "img-src 'self' data: https://*.tile.openstreetmap.org https://unpkg.com; "
            "connect-src 'self' https://nominatim.openstreetmap.org; "
            "font-src 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        return response

load_dotenv()
sys.path.insert(0, "src")
from zeekr_ev_api.client import ZeekrClient

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# ── Helpers ────────────────────────────────────────────────────────────────────

def _sf(val, default=None):
    """Safe float."""
    if val is None or val == "" or val == "None":
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


# ── GCJ-02 → WGS-84 Coordinate Conversion ────────────────────────────────────
# Zeekr's Chinese backend returns GCJ-02 ("Mars") coordinates.
# OpenStreetMap uses WGS-84. Without conversion, the car shows ~300m off.
import math

_GCJ_A = 6378245.0
_GCJ_EE = 0.00669342162296594


def _gcj_out_of_china(lat, lon):
    return not (73.66 < lon < 136.05 and 3.86 < lat < 53.55)


def _gcj_transform_lat(x, y):
    ret = -100.0 + 2.0 * x + 3.0 * y + 0.2 * y * y + 0.1 * x * y + 0.2 * math.sqrt(abs(x))
    ret += (20.0 * math.sin(6.0 * x * math.pi) + 20.0 * math.sin(2.0 * x * math.pi)) * 2.0 / 3.0
    ret += (20.0 * math.sin(y * math.pi) + 40.0 * math.sin(y / 3.0 * math.pi)) * 2.0 / 3.0
    ret += (160.0 * math.sin(y / 12.0 * math.pi) + 320.0 * math.sin(y * math.pi / 30.0)) * 2.0 / 3.0
    return ret


def _gcj_transform_lon(x, y):
    ret = 300.0 + x + 2.0 * y + 0.1 * x * x + 0.1 * x * y + 0.1 * math.sqrt(abs(x))
    ret += (20.0 * math.sin(6.0 * x * math.pi) + 20.0 * math.sin(2.0 * x * math.pi)) * 2.0 / 3.0
    ret += (20.0 * math.sin(x * math.pi) + 40.0 * math.sin(x / 3.0 * math.pi)) * 2.0 / 3.0
    ret += (150.0 * math.sin(x / 12.0 * math.pi) + 300.0 * math.sin(x / 30.0 * math.pi)) * 2.0 / 3.0
    return ret


def gcj02_to_wgs84(lat, lon):
    """Convert GCJ-02 coordinates to WGS-84."""
    if lat is None or lon is None:
        return lat, lon
    lat, lon = float(lat), float(lon)
    if _gcj_out_of_china(lat, lon):
        return lat, lon  # Outside China: likely already WGS-84
    d_lat = _gcj_transform_lat(lon - 105.0, lat - 35.0)
    d_lon = _gcj_transform_lon(lon - 105.0, lat - 35.0)
    rad_lat = lat / 180.0 * math.pi
    magic = math.sin(rad_lat)
    magic = 1 - _GCJ_EE * magic * magic
    sqrt_magic = math.sqrt(magic)
    d_lat = (d_lat * 180.0) / ((_GCJ_A * (1 - _GCJ_EE)) / (magic * sqrt_magic) * math.pi)
    d_lon = (d_lon * 180.0) / (_GCJ_A / sqrt_magic * math.cos(rad_lat) * math.pi)
    return lat - d_lat, lon - d_lon


def _si(val, default=None):
    """Safe int."""
    f = _sf(val)
    return round(f) if f is not None else default


def normalize_status(status: dict, charging: dict, vehicle, rc_state: dict = None) -> dict:
    """Parse raw Zeekr API status into clean, predictable fields."""
    basic = status.get("basicVehicleStatus", {})
    add = status.get("additionalVehicleStatus", {})
    ev = add.get("electricVehicleStatus", {})
    safety = add.get("drivingSafetyStatus", {})
    maint = add.get("maintenanceStatus", {})
    clim = add.get("climateStatus", {})
    poll = add.get("pollutionStatus", {})
    pos = basic.get("position", {})

    # Battery
    soc = _sf(ev.get("chargeLevel") or ev.get("stateOfCharge"))
    soc = round(soc) if soc is not None and soc > 0 else None

    # Lock & Doors
    lock_str = safety.get("centralLockingStatus")
    locked = lock_str not in ("0", "", None) if lock_str is not None and lock_str != "" else None

    def _door(open_key, lock_key):
        ov = safety.get(open_key)
        lv = safety.get(lock_key)
        return {
            "open": str(ov) == "2" if ov else False,  # 0=dicht+locked, 1=dicht+unlocked, 2=fysiek open
            "locked": lv not in ("0", "", None) if lv else None,
        }

    def _win(key):
        val = clim.get(key)
        pos = _si(clim.get(key.replace("Status", "Pos")))
        if val is None and pos is None:
            return None
        # winPos is betrouwbaar: 0=dicht, >0=open. winStatus codes wisselen per firmware.
        closed = (pos is not None and pos == 0) if pos is not None else False
        return {"closed": closed, "pos": pos}

    # Charging
    charge_power = _sf(charging.get("chargePower"), 0.0)
    time_to_full_str = ev.get("timeToFullyCharged")
    time_to_full = _si(time_to_full_str) if time_to_full_str != "2047" else None

    # Climate details
    steering_heat = clim.get("steerWhlHeatingSts")
    seat_heat_drv = clim.get("drvHeatDetail")
    seat_heat_pass = clim.get("passHeatingDetail")
    seat_vent_drv = clim.get("drvVentSts")

    # Tyres
    tyres = {}
    for label, suffix in [("driverFront", "Driver"), ("passengerFront", "Passenger"),
                          ("driverRear", "DriverRear"), ("passengerRear", "PassengerRear")]:
        p = _sf(maint.get(f"tyreStatus{suffix}"))
        tyres[label] = {
            "pressure_bar": round(p / 100, 2) if p else None,
            "temp": _si(maint.get(f"tyreTemp{suffix}")),
            "warning": str(maint.get(f"tyrePreWarning{suffix}", "0")) not in ("0", "", "None"),
        }

    main_batt = maint.get("mainBatteryStatus", {})

    return {
        "vin": vehicle.vin,
        "model": vehicle.data.get("modelName") or vehicle.data.get("vehicleModelName") or "Zeekr X",
        "plate": vehicle.data.get("plateNo", ""),
        "soc": soc,
        "range_km": _si(ev.get("distanceToEmptyOnBatteryOnly")),
        "avg_consumption_kwh": _sf(ev.get("averPowerConsumption")),
        "odometer_km": _si(maint.get("odometer")),
        "dist_service_km": _si(maint.get("distanceToService")),
        "days_to_service": _si(maint.get("daysToService")),
        "locked": locked,
        "doors": {
            "driverFront": _door("doorOpenStatusDriver", "doorLockStatusDriver"),
            "passengerFront": _door("doorOpenStatusPassenger", "doorLockStatusPassenger"),
            "driverRear": _door("doorOpenStatusDriverRear", "doorLockStatusDriverRear"),
            "passengerRear": _door("doorOpenStatusPassengerRear", "doorLockStatusPassengerRear"),
        },
        "trunk_open": safety.get("trunkOpenStatus") not in ("0", "", None) if safety.get("trunkOpenStatus") else None,
        "hood_open": safety.get("engineHoodOpenStatus") not in ("0", "", None) if safety.get("engineHoodOpenStatus") else None,
        "windows": {
            "driverFront": _win("winStatusDriver"),
            "passengerFront": _win("winStatusPassenger"),
            "driverRear": _win("winStatusDriverRear"),
            "passengerRear": _win("winStatusPassengerRear"),
        },
        "sunroof": {
            "closed": str(clim.get("sunroofOpenStatus")) == "1" if clim.get("sunroofOpenStatus") else None,
            "pos": _si(clim.get("sunroofPos")),
        },
        "is_charging": ev.get("isCharging", False),
        "is_plugged": ev.get("isPluggedIn", False),
        "charge_power_kw": round(charge_power, 1),
        "charge_voltage": _sf(charging.get("chargeVoltage"), 0.0),
        "charge_current": _sf(charging.get("chargeCurrent"), 0.0),
        "charge_speed": _si(charging.get("chargeSpeed")),
        "time_to_full_min": time_to_full,
        "charge_lid_ac": ev.get("chargeLidAcStatus"),
        "charge_lid_dc": ev.get("chargeLidDcAcStatus"),
        "interior_temp": _sf(clim.get("interiorTemp")),
        "airco_active": clim.get("preClimateActive") is True,
        "defrost": str(clim.get("defrost")) == "1",
        "steering_heat": str(steering_heat) == "1",
        "seat_heat_driver": str(seat_heat_drv) == "1",
        "seat_heat_passenger": str(seat_heat_pass) == "1",
        "seat_vent_driver": str(seat_vent_drv) == "1",
        "overheat_protect": clim.get("climateOverHeatProActive"),
        "fragrance_active": clim.get("fragStrs", {}).get("activated") == 1 if clim.get("fragStrs") else None,
        "tyres": tyres,
        "battery_12v": _sf(main_batt.get("voltage")) if main_batt else None,
        "pm25_interior": _si(poll.get("interiorPM25Level")),
        "location": (lambda la, lo: {"lat": la, "lon": lo})(*gcj02_to_wgs84(_sf(pos.get("latitude")), _sf(pos.get("longitude")))) if pos.get("latitude") else None,
        "vehicle_photo": vehicle.data.get("vehiclePhotoBig") or vehicle.data.get("vehiclePhotoSmall"),
        "color_name": vehicle.data.get("colorName"),
        "color_code": vehicle.data.get("colorCode"),
        "sentry_active": str((rc_state or {}).get("vstdModeState", "0")) == "1",
        "timestamp": int(time.time() * 1000),
    }


# ── Session & Multi-User State ────────────────────────────────────────────────
SESSION_COOKIE = "zeekr_session"
SESSION_SECRET = os.environ.get("SESSION_SECRET", secrets.token_hex(32))

# Per-session state: {session_token: {client, cached_data, cached_location, last_updated, username}}
sessions: Dict[str, Dict[str, Any]] = {}

# Schedules: {session_token: {"defrost": {...}, "charge": {...}}}
schedules: Dict[str, Dict[str, Any]] = {}

# ── User Preferences (persistent, per email) ─────────────────────────────────
PREFS_FILE = os.path.join(os.path.dirname(__file__), "..", "user_prefs.json")

def _load_prefs() -> Dict[str, Any]:
    try:
        if os.path.exists(PREFS_FILE):
            with open(PREFS_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def _save_prefs(prefs: Dict[str, Any]):
    try:
        with open(PREFS_FILE, "w", encoding="utf-8") as f:
            json.dump(prefs, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"Prefs opslaan mislukt: {e}")


def _run_scheduled_action(token: str, schedule_type: str, config: dict):
    """Execute a scheduled action for a session."""
    sess = sessions.get(token)
    if not sess:
        return
    try:
        v = _get_active_vehicle(sess)
        if not v:
            return
        if schedule_type == "climate":
            mode = config.get("mode", "defrost")
            if mode == "defrost":
                v.do_remote_control(
                    command="start", serviceID="ZAF",
                    setting={"serviceParameters": [
                        {"key": "DF", "value": "true"}, {"key": "DF.level", "value": "2"},
                        {"key": "RW", "value": "true"}, {"key": "AC", "value": "true"},
                    ]})
                logger.info(f"Scheduled defrost uitgevoerd voor {sess['username']}")
            else:
                temp = str(config.get("temperature", 22))
                dur = str(config.get("duration_min", 15))
                params = [
                    {"key": "operation", "value": "4"},
                    {"key": "AC", "value": "true"},
                    {"key": "AC.temp", "value": temp},
                    {"key": "AC.duration", "value": dur},
                ]
                sh_drv = config.get("seat_heat_driver", 0)
                if sh_drv > 0:
                    params += [{"key": "SH.driver", "value": "true"}, {"key": "SH.driver.level", "value": str(sh_drv)}, {"key": "SH.driver.duration", "value": dur}]
                sh_pass = config.get("seat_heat_passenger", 0)
                if sh_pass > 0:
                    params += [{"key": "SH.passenger", "value": "true"}, {"key": "SH.passenger.level", "value": str(sh_pass)}, {"key": "SH.passenger.duration", "value": dur}]
                sw = config.get("steering_heat", 0)
                if sw > 0:
                    params += [{"key": "SW", "value": "true"}, {"key": "SW.level", "value": str(sw)}, {"key": "SW.duration", "value": dur}]
                v.do_remote_control(command="start", serviceID="ZAF", setting={"serviceParameters": params})
                # Seat ventilation via separate ZAF call (different param format)
                sv_drv = config.get("seat_vent_driver", 0)
                sv_pass = config.get("seat_vent_passenger", 0)
                if sv_drv > 0 or sv_pass > 0:
                    sv_params = []
                    if sv_drv > 0:
                        sv_params += [{"key": "SV.driver", "value": "true"}, {"key": "SV.driver.level", "value": str(sv_drv)}]
                    if sv_pass > 0:
                        sv_params += [{"key": "SV.passenger", "value": "true"}, {"key": "SV.passenger.level", "value": str(sv_pass)}]
                    v.do_remote_control(command="start", serviceID="ZAF", setting={"serviceParameters": sv_params})
                logger.info(f"Scheduled climate ({temp}°C, {dur}min) uitgevoerd voor {sess['username']}")
        elif schedule_type == "charge":
            v.do_remote_control(
                command="start", serviceID="RCS",
                setting={"serviceParameters": [
                    {"key": "rcs.restart", "value": "1"},
                ]})
            limit = config.get("limit")
            if limit and limit != 80:
                v.do_remote_control(
                    command="start", serviceID="RCS",
                    setting={"serviceParameters": [
                        {"key": "rcs.setting", "value": "1"},
                        {"key": "soc", "value": str(limit)},
                    ]})
            logger.info(f"Scheduled charge uitgevoerd voor {sess['username']}")
    except Exception as e:
        logger.error(f"Scheduled {schedule_type} mislukt: {e}")


def _stop_charge_action(token: str):
    """Stop charging at scheduled time_to."""
    try:
        sess = sessions.get(token)
        if not sess:
            return
        v = _get_active_vehicle(sess)
        if not v:
            return
        v.do_remote_control(
            command="stop", serviceID="RCS",
            setting={"serviceParameters": [
                {"key": "rcs.terminate", "value": "1"},
            ]})
        logger.info(f"Scheduled charge STOP uitgevoerd voor {sess['username']}")
    except Exception as e:
        logger.error(f"Scheduled charge stop mislukt: {e}")


def _scheduler_loop():
    """Background scheduler — check every 30 seconds if a scheduled action should fire."""
    while True:
        try:
            now = datetime.now()
            current_hm = now.strftime("%H:%M")
            current_dow = now.weekday()  # 0=Monday

            for token, user_schedules in list(schedules.items()):
                for stype, cfg in list(user_schedules.items()):
                    if not cfg.get("enabled"):
                        continue
                    repeat = cfg.get("repeat", "daily")
                    if repeat == "weekdays" and current_dow >= 5:
                        continue
                    today = now.strftime("%Y-%m-%d")

                    if stype == "charge":
                        # Charge: van-tot tijdvenster
                        time_from = cfg.get("time_from") or cfg.get("time")
                        time_to = cfg.get("time_to")
                        if not time_from:
                            continue
                        # Start laden op time_from
                        if time_from == current_hm and cfg.get("_last_start") != today:
                            cfg["_last_start"] = today
                            _run_scheduled_action(token, stype, cfg)
                            if repeat == "once":
                                cfg["enabled"] = False
                        # Stop laden op time_to
                        if time_to and time_to == current_hm and cfg.get("_last_stop") != today:
                            cfg["_last_stop"] = today
                            _stop_charge_action(token)
                    else:
                        # Climate/overig: enkele trigger tijd
                        if not cfg.get("time") or cfg["time"] != current_hm:
                            continue
                        if cfg.get("_last_fired") == today:
                            continue
                        cfg["_last_fired"] = today
                        _run_scheduled_action(token, stype, cfg)
                        if repeat == "once":
                            cfg["enabled"] = False
        except Exception as e:
            logger.error(f"Scheduler fout: {e}")
        time.sleep(30)


_scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
_scheduler_thread.start()


def _get_session(request: Request) -> Optional[Dict[str, Any]]:
    """Get session from cookie, fall back to default session from session.json."""
    token = request.cookies.get(SESSION_COOKIE)
    if token and token in sessions:
        return sessions[token]
    # Fallback: use the auto-loaded session from session.json
    default_token = getattr(request.app.state, "default_session_token", None)
    if default_token and default_token in sessions:
        return sessions[default_token]
    return None


def _create_session(username: str, client: ZeekrClient) -> str:
    """Create a new session, return token."""
    token = secrets.token_urlsafe(48)
    # Fetch vehicle list once at session creation
    vehicles = []
    try:
        vehicles = client.get_vehicle_list()
    except Exception as e:
        logger.warning(f"Vehicle list ophalen mislukt voor {username}: {e}")
    sessions[token] = {
        "client": client,
        "username": username,
        "vehicles": vehicles,
        "active_vin": vehicles[0].vin if vehicles else None,
        "cached_data": {},
        "cached_location": {},
        "last_updated": None,
    }
    logger.info(f"Session created for {username} — {len(vehicles)} voertuig(en)")
    return token



def init_client_from_env() -> Optional[ZeekrClient]:
    """Try to init client from session file or env vars (legacy/startup)."""
    session_file = os.path.join(os.path.dirname(__file__), "session.json")
    if os.path.exists(session_file):
        try:
            with open(session_file, "r", encoding="utf-8") as f:
                session_data = json.load(f)
            if session_data.get("bearer_token"):
                c = ZeekrClient(session_data=session_data)
                logger.info(f"Loaded session for {session_data.get('username', '?')}")
                return c
        except Exception as e:
            logger.warning(f"Session laden mislukt: {e}")

    email = os.environ.get("ZEEKR_EMAIL")
    password = os.environ.get("ZEEKR_PASSWORD")
    if email and password:
        country = os.environ.get("ZEEKR_COUNTRY", "NL")
        c = ZeekrClient(username=email, password=password, country_code=country)
        c.login()
        logger.info(f"Logged in as {email}")
        return c
    return None


def _get_active_vehicle(sess: Dict[str, Any]):
    """Get the active vehicle from session cache, refresh if needed."""
    vehicles = sess.get("vehicles", [])
    if not vehicles:
        # Refresh vehicle list
        vehicles = sess["client"].get_vehicle_list()
        sess["vehicles"] = vehicles
        if vehicles and not sess.get("active_vin"):
            sess["active_vin"] = vehicles[0].vin
    active_vin = sess.get("active_vin")
    for v in vehicles:
        if v.vin == active_vin:
            return v
    return vehicles[0] if vehicles else None


def fetch_vehicle_data(sess: Dict[str, Any]) -> Dict[str, Any]:
    v = _get_active_vehicle(sess)
    if not v:
        return {"error": "Geen voertuigen gevonden"}
    try:
        status = v.get_status() or {}
    except Exception as e:
        status = {"error": str(e)}
    try:
        charging = v.get_charging_status() or {}
    except Exception as e:
        charging = {"error": str(e)}
    try:
        rc_state = v.get_remote_control_state() or {}
    except Exception as e:
        rc_state = {}

    try:
        parsed = normalize_status(status, charging, vehicle=v, rc_state=rc_state)
    except Exception as e:
        parsed = {"error": str(e)}


    data = {
        "vin": v.vin,
        "vehicle_info": v.data,
        "status": status,
        "charging": charging,
        "parsed": parsed,
    }
    sess["cached_data"] = data
    sess["last_updated"] = datetime.now()
    return data


def fetch_location_data(sess: Dict[str, Any]) -> Dict[str, Any]:
    v = _get_active_vehicle(sess)
    if not v:
        return {"error": "Geen voertuigen gevonden"}

    lat, lon, ts, source = None, None, None, None

    # Source 1: Real-time vehicle status position (most accurate)
    cached = sess.get("cached_data")
    if cached and isinstance(cached, dict):
        parsed = cached.get("parsed", {})
        loc = parsed.get("location")
        if loc and loc.get("lat") and loc.get("lon"):
            lat, lon = loc["lat"], loc["lon"]
            ts = cached.get("timestamp") or parsed.get("timestamp")
            source = "live"

    # Source 2: Journey log (fallback — end of last trip)
    if lat is None or lon is None:
        try:
            journal = v.get_journey_log(page_size=5, current_page=1)
        except Exception as e:
            if lat is None:
                return {"error": str(e)}
            journal = None

        if journal:
            trips = None
            for key in ("data", "records", "list", "rows", "result", "items"):
                if isinstance(journal, dict) and key in journal:
                    val = journal[key]
                    if isinstance(val, list) and val:
                        trips = val
                        break
            if trips is None and isinstance(journal, list) and journal:
                trips = journal

            if trips:
                trip = trips[0]
                lat = trip.get("endLatitude") or trip.get("endLat")
                lon = trip.get("endLongitude") or trip.get("endLon")

                if (lat is None or lon is None) and "trackPoints" in trip:
                    tp = trip["trackPoints"]
                    if isinstance(tp, list) and tp:
                        last = tp[-1]
                        if lat is None and "latitude" in last:
                            lat = last["latitude"]
                        if lon is None and "longitude" in last:
                            lon = last["longitude"]

                for ts_key in ("endTime", "end_time", "tripEndTime", "timestamp", "createTime"):
                    if ts_key in trip:
                        ts = trip[ts_key]
                        break
                source = "trip"

    if lat is None or lon is None:
        return {"error": "Geen locatiedata beschikbaar"}

    # Convert GCJ-02 → WGS-84 (Zeekr backend uses Chinese coordinate system)
    lat, lon = gcj02_to_wgs84(lat, lon)

    result = {"lat": lat, "lon": lon, "timestamp": ts, "source": source}
    sess["cached_location"] = result
    return result


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Auto-login from env if available (backwards compat)
    try:
        c = init_client_from_env()
        if c:
            username = os.environ.get("ZEEKR_EMAIL", "owner")
            token = _create_session(username, c)
            # Store default token for env-based login
            app.state.default_session_token = token
            fetch_vehicle_data(sessions[token])
    except Exception as e:
        logger.error(f"Startup fout: {e}")
    yield


app = FastAPI(title="Zeekr Dashboard", lifespan=lifespan)
app.add_middleware(SecurityMiddleware)
app.mount("/static", StaticFiles(directory="static"), name="static")


# ── HTML Dashboard ─────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="nl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Zeekr X Dashboard</title>
<link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css"/>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #0a0a0f;
    color: #e2e8f0;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 2rem 1rem;
  }
  header {
    text-align: center;
    margin-bottom: 2rem;
  }
  header h1 {
    font-size: 2rem;
    font-weight: 700;
    letter-spacing: -0.5px;
    color: #fff;
  }
  header .vin {
    font-size: 0.75rem;
    color: #64748b;
    margin-top: 0.25rem;
    font-family: monospace;
  }
  .grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 1rem;
    width: 100%;
    max-width: 900px;
  }
  .card {
    background: #141420;
    border: 1px solid #1e1e2e;
    border-radius: 16px;
    padding: 1.5rem;
    transition: border-color 0.2s;
  }
  .card:hover { border-color: #3b82f6; }
  .card .label {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #64748b;
    margin-bottom: 0.75rem;
  }
  .card .value {
    font-size: 2.4rem;
    font-weight: 700;
    line-height: 1;
  }
  .card .unit {
    font-size: 0.9rem;
    color: #94a3b8;
    margin-top: 0.25rem;
  }
  .soc-bar {
    margin-top: 0.75rem;
    height: 6px;
    background: #1e1e2e;
    border-radius: 3px;
    overflow: hidden;
  }
  .soc-fill {
    height: 100%;
    border-radius: 3px;
    transition: width 0.6s ease;
  }
  .status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 6px;
  }
  .green { color: #22c55e; }
  .yellow { color: #f59e0b; }
  .blue { color: #3b82f6; }
  .gray { color: #64748b; }
  .bg-green { background: #22c55e; }
  .bg-yellow { background: #f59e0b; }
  .bg-blue { background: #3b82f6; }
  .bg-gray { background: #64748b; }
  .wide { grid-column: 1 / -1; }
  .raw {
    background: #0f0f1a;
    border: 1px solid #1e1e2e;
    border-radius: 12px;
    padding: 1rem;
    font-family: monospace;
    font-size: 0.7rem;
    color: #64748b;
    max-height: 300px;
    overflow-y: auto;
    white-space: pre-wrap;
    word-break: break-all;
    margin-top: 1rem;
    width: 100%;
    max-width: 900px;
  }
  .refresh-btn {
    margin-top: 1.5rem;
    padding: 0.6rem 1.5rem;
    background: #3b82f6;
    color: white;
    border: none;
    border-radius: 8px;
    font-size: 0.85rem;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
  }
  .refresh-btn:hover { background: #2563eb; }
  .refresh-btn:disabled { background: #334155; cursor: not-allowed; }
  .updated { font-size: 0.7rem; color: #475569; margin-top: 0.5rem; }
  .error-card { border-color: #ef4444 !important; }
  .error-card .value { font-size: 1rem; color: #ef4444; }
  .card-map { padding: 0; overflow: hidden; cursor: pointer; }
  .card-map.expanded { grid-column: 1 / -1; }
  .card-map.expanded #map { height: 500px; }
  .card-map .label { padding: 1.5rem 1.5rem 0.75rem; }
  #map { height: 260px; transition: height 0.3s ease; touch-action: none; }
  .loc-info { padding: 0.5rem 1.5rem 1rem; font-size: 0.72rem; color: #64748b; }

  /* Controls */
  .controls {
    width: 100%;
    max-width: 900px;
    margin-top: 2rem;
  }
  .controls h2 {
    font-size: 1.1rem;
    font-weight: 600;
    color: #94a3b8;
    margin-bottom: 1rem;
    padding-left: 0.25rem;
  }
  .ctrl-group {
    background: #141420;
    border: 1px solid #1e1e2e;
    border-radius: 16px;
    padding: 1.25rem;
    margin-bottom: 1rem;
  }
  .ctrl-group .group-title {
    font-size: 0.7rem;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: #64748b;
    margin-bottom: 0.75rem;
  }
  .ctrl-row {
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    align-items: center;
  }
  .ctrl-btn {
    padding: 0.5rem 1rem;
    border: 1px solid #2d2d3f;
    border-radius: 10px;
    background: #1a1a2e;
    color: #e2e8f0;
    font-size: 0.8rem;
    font-weight: 500;
    cursor: pointer;
    transition: all 0.2s;
    display: flex;
    align-items: center;
    gap: 0.4rem;
  }
  .ctrl-btn:hover { background: #252540; border-color: #3b82f6; }
  .ctrl-btn:active { transform: scale(0.97); }
  .ctrl-btn:disabled { opacity: 0.4; cursor: not-allowed; }
  .ctrl-btn.danger { border-color: #7f1d1d; }
  .ctrl-btn.danger:hover { border-color: #ef4444; background: #1a0a0a; }
  .ctrl-btn.success { border-color: #14532d; }
  .ctrl-btn.success:hover { border-color: #22c55e; background: #0a1a0a; }
  .ctrl-select {
    padding: 0.45rem 0.6rem;
    border: 1px solid #2d2d3f;
    border-radius: 8px;
    background: #1a1a2e;
    color: #e2e8f0;
    font-size: 0.8rem;
  }
  .ctrl-input {
    padding: 0.45rem 0.6rem;
    border: 1px solid #2d2d3f;
    border-radius: 8px;
    background: #1a1a2e;
    color: #e2e8f0;
    font-size: 0.8rem;
    width: 70px;
    text-align: center;
  }
  .toast {
    position: fixed;
    bottom: 2rem;
    left: 50%;
    transform: translateX(-50%) translateY(100px);
    background: #1e293b;
    color: #e2e8f0;
    border: 1px solid #334155;
    border-radius: 12px;
    padding: 0.75rem 1.5rem;
    font-size: 0.85rem;
    z-index: 9999;
    transition: transform 0.3s ease;
    pointer-events: none;
  }
  .toast.show { transform: translateX(-50%) translateY(0); }
  .toast.ok { border-color: #22c55e; }
  .toast.err { border-color: #ef4444; }

  /* Climate grid */
  .climate-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(80px, 1fr));
    gap: 8px;
    margin-top: 8px;
  }
  .climate-item {
    text-align: center;
    padding: 6px 2px;
    border-radius: 8px;
    background: rgba(255,255,255,0.03);
  }
  .climate-icon { font-size: 1.3rem; }
  .climate-val { font-size: 0.95rem; font-weight: 600; color: #e2e8f0; margin: 2px 0; }
  .climate-lbl { font-size: 0.65rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; }
  .climate-val .green { color: #22c55e; }
  .climate-val .red { color: #ef4444; }
  .climate-val .yellow { color: #eab308; }
  .climate-val .dim { color: #64748b; }

  /* Toggle switch */
  .toggle-switch { position: relative; display: inline-block; width: 48px; height: 26px; flex-shrink: 0; }
  .toggle-switch input { opacity: 0; width: 0; height: 0; }
  .toggle-slider { position: absolute; cursor: pointer; inset: 0; background: #334155; border-radius: 26px; transition: 0.3s; }
  .toggle-slider::before { content: ""; position: absolute; height: 20px; width: 20px; left: 3px; bottom: 3px; background: #94a3b8; border-radius: 50%; transition: 0.3s; }
  .toggle-switch input:checked + .toggle-slider { background: #22c55e; }
  .toggle-switch input:checked + .toggle-slider::before { transform: translateX(22px); background: #fff; }
</style>
</head>
<body>
<header>
  <h1>⚡ Zeekr X</h1>
  <div class="vin" id="vin">Laden...</div>
</header>

<div class="grid" id="grid">
  <div class="card" id="card-soc">
    <div class="label">Batterij</div>
    <div class="value" id="soc">—</div>
    <div class="unit">%</div>
    <div class="soc-bar"><div class="soc-fill" id="soc-fill" style="width:0%"></div></div>
  </div>
  <div class="card" id="card-range">
    <div class="label">Bereik</div>
    <div class="value" id="range">—</div>
    <div class="unit">km resterend</div>
  </div>
  <div class="card" id="card-charging">
    <div class="label">Laadstatus</div>
    <div class="value" id="charging-status">—</div>
    <div class="unit" id="charging-power"></div>
  </div>
  <div class="card" id="card-odometer">
    <div class="label">Kilometerstand</div>
    <div class="value" id="odometer">—</div>
    <div class="unit">km</div>
  </div>
  <div class="card" id="card-locked">
    <div class="label">Vergrendeld</div>
    <div class="value" id="locked">—</div>
  </div>
  <div class="card wide" id="card-climate">
    <div class="label">Klimaat</div>
    <div class="climate-grid">
      <div class="climate-item">
        <div class="climate-icon">🌡️</div>
        <div class="climate-val" id="clim-interior">—</div>
        <div class="climate-lbl">Interieur</div>
      </div>
      <div class="climate-item">
        <div class="climate-icon">🌤️</div>
        <div class="climate-val" id="clim-outside">—</div>
        <div class="climate-lbl">Buiten</div>
      </div>
      <div class="climate-item">
        <div class="climate-icon">🫁</div>
        <div class="climate-val" id="clim-pm25">—</div>
        <div class="climate-lbl">PM2.5</div>
      </div>
      <div class="climate-item">
        <div class="climate-icon">❄️</div>
        <div class="climate-val" id="clim-airco">—</div>
        <div class="climate-lbl">Klimaat</div>
      </div>
      <div class="climate-item">
        <div class="climate-icon">🧊</div>
        <div class="climate-val" id="clim-defrost">—</div>
        <div class="climate-lbl">Ontdooien</div>
      </div>
      <div class="climate-item">
        <div class="climate-icon">🔥</div>
        <div class="climate-val" id="clim-seat-heat">—</div>
        <div class="climate-lbl">Stoelverw.</div>
      </div>
      <div class="climate-item">
        <div class="climate-icon">💨</div>
        <div class="climate-val" id="clim-seat-vent">—</div>
        <div class="climate-lbl">Stoelvent.</div>
      </div>
      <div class="climate-item">
        <div class="climate-icon">🎡</div>
        <div class="climate-val" id="clim-steering">—</div>
        <div class="climate-lbl">Stuurverw.</div>
      </div>
      <div class="climate-item">
        <div class="climate-icon">🌸</div>
        <div class="climate-val" id="clim-fragrance">—</div>
        <div class="climate-lbl">Geur</div>
      </div>
      <div class="climate-item">
        <div class="climate-icon">☀️</div>
        <div class="climate-val" id="clim-sunroof">—</div>
        <div class="climate-lbl">Zonnedak</div>
      </div>
      <div class="climate-item">
        <div class="climate-icon">🛡️</div>
        <div class="climate-val" id="clim-overheat">—</div>
        <div class="climate-lbl">Overhit besch.</div>
      </div>
    </div>
  </div>
  <div class="card card-map wide" id="card-location">
    <div class="label">Laatste bekende locatie</div>
    <div id="map"></div>
    <div class="loc-info" id="loc-info">Laden...</div>
  </div>
</div>

<!-- Controls -->
<div class="controls">
  <h2>Bediening</h2>

  <!-- Deuren -->
  <div class="ctrl-group">
    <div class="group-title">Deuren</div>
    <div class="ctrl-row">
      <button class="ctrl-btn success" onclick="ctrl('lock')">🔒 Vergrendelen</button>
      <button class="ctrl-btn danger" onclick="ctrl('unlock')">🔓 Ontgrendelen</button>
      <button class="ctrl-btn" onclick="ctrl('find')">📍 Vinden (claxon)</button>
    </div>
  </div>

  <!-- Klimaat -->
  <div class="ctrl-group">
    <div class="group-title">Klimaat</div>
    <div class="ctrl-row" style="align-items:center;">
      <span style="color:#94a3b8;font-size:0.85rem;">🌡️ Voorverwarmen</span>
      <label class="toggle-switch">
        <input type="checkbox" id="preheat-toggle" onchange="togglePreheat(this.checked)">
        <span class="toggle-slider"></span>
      </label>
      <input type="number" id="preheat-temp" class="ctrl-input" value="22" min="16" max="30" step="0.5"> <span style="color:#64748b;font-size:0.75rem">°C</span>
    </div>
  </div>

  <!-- Stoelverwarming -->
  <div class="ctrl-group">
    <div class="group-title">Stoelverwarming</div>
    <div class="ctrl-row">
      <span style="color:#64748b;font-size:0.75rem">Bestuurder:</span>
      <select id="seat-heat-fl" class="ctrl-select">
        <option value="0">Uit</option>
        <option value="1">Laag</option>
        <option value="2">Midden</option>
        <option value="3">Hoog</option>
      </select>
      <span style="color:#64748b;font-size:0.75rem">Passagier:</span>
      <select id="seat-heat-fr" class="ctrl-select">
        <option value="0">Uit</option>
        <option value="1">Laag</option>
        <option value="2">Midden</option>
        <option value="3">Hoog</option>
      </select>
      <button class="ctrl-btn" onclick="ctrl('seat_heating', {seat_fl: +document.getElementById('seat-heat-fl').value, seat_fr: +document.getElementById('seat-heat-fr').value})">🔥 Instellen</button>
    </div>
  </div>

  <!-- Stoelventilatie -->
  <div class="ctrl-group">
    <div class="group-title">Stoelventilatie</div>
    <div class="ctrl-row">
      <span style="color:#64748b;font-size:0.75rem">Bestuurder:</span>
      <select id="seat-vent-fl" class="ctrl-select">
        <option value="0">Uit</option>
        <option value="1">Laag</option>
        <option value="2">Midden</option>
        <option value="3">Hoog</option>
      </select>
      <span style="color:#64748b;font-size:0.75rem">Passagier:</span>
      <select id="seat-vent-fr" class="ctrl-select">
        <option value="0">Uit</option>
        <option value="1">Laag</option>
        <option value="2">Midden</option>
        <option value="3">Hoog</option>
      </select>
      <button class="ctrl-btn" onclick="ctrl('seat_ventilation', {seat_fl: +document.getElementById('seat-vent-fl').value, seat_fr: +document.getElementById('seat-vent-fr').value})">💨 Instellen</button>
    </div>
  </div>

  <!-- Stuurverwarming -->
  <div class="ctrl-group">
    <div class="group-title">Stuurverwarming</div>
    <div class="ctrl-row">
      <select id="steering-level" class="ctrl-select">
        <option value="0">Uit</option>
        <option value="1">Laag</option>
        <option value="2">Midden</option>
        <option value="3">Hoog</option>
      </select>
      <button class="ctrl-btn" onclick="ctrl('steering_heating', {level: +document.getElementById('steering-level').value})">🔥 Instellen</button>
    </div>
  </div>

  <!-- Ventilatiestand -->
  <div class="ctrl-group">
    <div class="group-title">Ventilatiestand (fan)</div>
    <div class="ctrl-row">
      <select id="fan-speed" class="ctrl-select">
        <option value="0">Uit / Auto</option>
        <option value="1">1</option>
        <option value="2">2</option>
        <option value="3">3</option>
        <option value="4">4</option>
        <option value="5">5</option>
        <option value="6">6</option>
        <option value="7">7</option>
      </select>
      <button class="ctrl-btn" onclick="ctrl('fan_speed', {level: +document.getElementById('fan-speed').value})">🌀 Instellen</button>
    </div>
  </div>

  <!-- Ontdooien -->
  <div class="ctrl-group">
    <div class="group-title">Ontdooien</div>
    <div class="ctrl-row">
      <button class="ctrl-btn" onclick="ctrl('defrost_front')">🧊 Voorruit</button>
      <button class="ctrl-btn" onclick="ctrl('defrost_rear')">🧊 Achterruit</button>
    </div>
  </div>

  <!-- Ramen -->
  <div class="ctrl-group">
    <div class="group-title">Ramen</div>
    <div class="ctrl-row">
      <button class="ctrl-btn danger" onclick="ctrl('open_windows', {percent: +document.getElementById('window-pct').value})">⬇️ Ramen open</button>
      <select id="window-pct" class="ctrl-select">
        <option value="25">25%</option>
        <option value="50">50%</option>
        <option value="75">75%</option>
        <option value="100" selected>100%</option>
      </select>
      <button class="ctrl-btn success" onclick="ctrl('close_windows')">⬆️ Ramen dicht</button>
    </div>
  </div>

  <!-- Laden -->
  <div class="ctrl-group">
    <div class="group-title">Laden</div>
    <div class="ctrl-row">
      <button class="ctrl-btn success" onclick="ctrl('start_charge')">⚡ Start laden</button>
      <button class="ctrl-btn danger" onclick="ctrl('stop_charge')">⏹️ Stop laden</button>
      <button class="ctrl-btn" onclick="ctrl('set_charge_limit', {limit: +document.getElementById('charge-limit').value})">🔋 Laadlimiet</button>
      <input type="number" id="charge-limit" class="ctrl-input" value="80" min="20" max="100" step="5"> <span style="color:#64748b;font-size:0.75rem">%</span>
    </div>
  </div>
</div>

<div id="toast" class="toast"></div>

<button class="refresh-btn" id="refresh-btn" onclick="loadData()">↻ Vernieuwen</button>
<div class="updated" id="updated"></div>

<details style="width:100%;max-width:900px;margin-top:1rem">
  <summary style="cursor:pointer;color:#475569;font-size:0.75rem;padding:0.5rem">Raw API data</summary>
  <div class="raw" id="raw-data">Laden...</div>
</details>

<script>
async function loadData() {
  const btn = document.getElementById('refresh-btn');
  btn.disabled = true;
  btn.textContent = 'Laden...';
  try {
    const res = await fetch('/api/status');
    const d = await res.json();
    renderData(d);
  } catch (e) {
    document.getElementById('raw-data').textContent = 'Fout: ' + e;
  }
  btn.disabled = false;
  btn.textContent = '↻ Vernieuwen';
}

function pick(obj, ...keys) {
  for (const k of keys) {
    if (obj && obj[k] !== undefined && obj[k] !== null) return obj[k];
    // nested
    for (const top of Object.values(obj || {})) {
      if (top && typeof top === 'object' && top[k] !== undefined) return top[k];
    }
  }
  return null;
}

function deepPick(obj, ...keys) {
  if (!obj || typeof obj !== 'object') return null;
  for (const k of keys) {
    if (obj[k] !== undefined && obj[k] !== null) return obj[k];
  }
  for (const v of Object.values(obj)) {
    const found = deepPick(v, ...keys);
    if (found !== null) return found;
  }
  return null;
}

function renderData(d) {
  document.getElementById('raw-data').textContent = JSON.stringify(d, null, 2);
  document.getElementById('vin').textContent = d.vin || 'Onbekend';

  const s = d.status || {};
  const c = d.charging || {};

  // SOC
  const soc = deepPick(s, 'soc', 'SOC', 'batteryLevel', 'battery_level', 'bms_soc')
             || deepPick(c, 'soc', 'SOC', 'batteryLevel');
  if (soc !== null) {
    const pct = Math.round(soc > 1 ? soc : soc * 100);
    document.getElementById('soc').textContent = pct;
    const fill = document.getElementById('soc-fill');
    fill.style.width = pct + '%';
    fill.className = 'soc-fill ' + (pct > 50 ? 'bg-green' : pct > 20 ? 'bg-yellow' : 'bg-red');
  }

  // Range
  const range = deepPick(s, 'range', 'cruisingRange', 'cruising_range', 'remainMile', 'remain_range', 'endurance', 'electricRange');
  if (range !== null) {
    document.getElementById('range').textContent = Math.round(range > 500 ? range / 1000 : range);
  }

  // Charging
  const chgStatus = deepPick(c, 'chargingStatus', 'charging_status', 'chargeStatus', 'isCharging', 'status');
  const chgPower = deepPick(c, 'chargingPower', 'charging_power', 'power', 'chargePower');
  const chgEl = document.getElementById('charging-status');
  if (chgStatus !== null) {
    const isCharging = chgStatus === true || chgStatus === 1 || chgStatus === 'CHARGING' || chgStatus === 'charging';
    chgEl.innerHTML = isCharging
      ? '<span class="status-dot bg-green"></span><span class="green">Aan het laden</span>'
      : '<span class="status-dot bg-gray"></span><span class="gray">Niet laden</span>';
    if (isCharging && chgPower) {
      document.getElementById('charging-power').textContent = Math.round(chgPower / 1000) + ' kW';
    }
  } else {
    chgEl.textContent = '—';
  }

  // Odometer
  const odo = deepPick(s, 'mileage', 'odometer', 'totalMileage', 'total_mileage');
  if (odo !== null) {
    document.getElementById('odometer').textContent = Math.round(odo > 100000 ? odo / 1000 : odo).toLocaleString('nl-NL');
  }

  // Locked
  const locked = deepPick(s, 'locked', 'doorLocked', 'door_locked', 'vehicleLocked');
  if (locked !== null) {
    const isLocked = locked === true || locked === 1 || locked === 'LOCKED';
    document.getElementById('locked').innerHTML = isLocked
      ? '<span class="green">🔒 Ja</span>'
      : '<span class="yellow">🔓 Nee</span>';
  }

  // Climate info grid
  const intTemp = deepPick(s, 'interior_temp');
  if (intTemp !== null) {
    const t = intTemp > 100 ? (intTemp / 10).toFixed(1) : intTemp.toFixed ? intTemp.toFixed(1) : intTemp;
    document.getElementById('clim-interior').textContent = t + '°C';
  }
  const outTemp = deepPick(s, 'outsideTemperature', 'outside_temp', 'exteriorTemperature', 'tempValue', 'temperature');
  if (outTemp !== null) {
    const t = (outTemp / 10 < -50 || outTemp / 10 > 60) ? outTemp : (outTemp / 10).toFixed(1);
    document.getElementById('clim-outside').textContent = t + '°C';
  }
  const pm25 = deepPick(s, 'pm25_interior');
  if (pm25 !== null) {
    let cls = 'green', lbl = 'Goed';
    if (pm25 > 75) { cls = 'red'; lbl = 'Slecht'; }
    else if (pm25 > 35) { cls = 'yellow'; lbl = 'Matig'; }
    document.getElementById('clim-pm25').innerHTML = '<span class="' + cls + '">' + pm25 + '</span> <span class="dim" style="font-size:0.7rem">' + lbl + '</span>';
  }
  const onOff = (v) => v ? '<span class="green">Aan</span>' : '<span class="dim">Uit</span>';
  document.getElementById('clim-airco').innerHTML = onOff(deepPick(s, 'airco_active'));
  document.getElementById('clim-defrost').innerHTML = onOff(deepPick(s, 'defrost'));
  document.getElementById('clim-seat-heat').innerHTML = onOff(deepPick(s, 'seat_heat_driver'));
  document.getElementById('clim-seat-vent').innerHTML = onOff(deepPick(s, 'seat_vent_driver'));
  document.getElementById('clim-steering').innerHTML = onOff(deepPick(s, 'steering_heat'));
  const frag = deepPick(s, 'fragrance_active');
  document.getElementById('clim-fragrance').innerHTML = frag === null ? '<span class="dim">—</span>' : onOff(frag);
  const oh = deepPick(s, 'overheat_protect');
  document.getElementById('clim-overheat').innerHTML = oh === null ? '<span class="dim">—</span>' : onOff(oh);
  const sr = deepPick(s, 'sunroof');
  if (sr) {
    document.getElementById('clim-sunroof').innerHTML = sr.closed ? '<span class="green">Dicht</span>' : '<span class="yellow">Open' + (sr.pos ? ' ' + sr.pos + '%' : '') + '</span>';
  }

  document.getElementById('updated').textContent = 'Bijgewerkt: ' + new Date().toLocaleTimeString('nl-NL');
}

loadData();
setInterval(loadData, 300000);

// ── Controls ──────────────────────────────────────────────────────────────
function showToast(msg, ok) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.className = 'toast show ' + (ok ? 'ok' : 'err');
  setTimeout(() => { t.className = 'toast'; }, 3000);
}

async function ctrl(action, body) {
  try {
    const res = await fetch('/api/control/' + action, {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(body || {}),
    });
    const d = await res.json();
    if (d.ok) {
      showToast('✅ ' + action.replace(/_/g, ' '), true);
      setTimeout(loadData, 2000);
    } else {
      showToast('❌ ' + (d.error || 'Fout'), false);
    }
  } catch (e) {
    showToast('❌ ' + e, false);
  }
}

async function togglePreheat(on) {
  const toggle = document.getElementById('preheat-toggle');
  if (on) {
    const temp = parseFloat(document.getElementById('preheat-temp').value);
    await ctrl('preheat', {temperature: temp});
  } else {
    await ctrl('stop_climate');
  }
}
</script>
<script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js"></script>
<script>
// Fix Leaflet default marker icon path when loaded from CDN
delete L.Icon.Default.prototype._getIconUrl;
L.Icon.Default.mergeOptions({
  iconUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon.png',
  iconRetinaUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-icon-2x.png',
  shadowUrl: 'https://unpkg.com/leaflet@1.9.4/dist/images/marker-shadow.png',
});
let map = null;
let marker = null;

// Expand/collapse map card — only on label click, not on map drag
(function() {
  const card = document.getElementById('card-location');
  const label = card.querySelector('.label');
  const locInfo = card.querySelector('.loc-info');

  // Only toggle when clicking the label or loc-info, NOT the map itself
  function toggleMap(e) {
    card.classList.toggle('expanded');
    if (map) {
      setTimeout(() => map.invalidateSize(), 350);
    }
  }
  label.style.cursor = 'pointer';
  locInfo.style.cursor = 'pointer';
  label.addEventListener('click', toggleMap);
  locInfo.addEventListener('click', toggleMap);

  // Prevent map interactions from bubbling to card
  const mapEl = document.getElementById('map');
  mapEl.addEventListener('mousedown', e => e.stopPropagation());
  mapEl.addEventListener('touchstart', e => e.stopPropagation(), {passive: true});
  card.style.cursor = 'default';
})();

async function loadLocation() {
  try {
    const res = await fetch('/api/location');
    const d = await res.json();
    if (d.lat !== null && d.lon !== null) {
      const lat = parseFloat(d.lat);
      const lon = parseFloat(d.lon);
      if (!map) {
        map = L.map('map').setView([lat, lon], 14);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
          maxZoom: 19, attribution: '© OpenStreetMap'
        }).addTo(map);
        marker = L.marker([lat, lon]).addTo(map);
        marker.bindPopup('⚡ Zeekr X').openPopup();
      } else {
        map.setView([lat, lon], 14);
        marker.setLatLng([lat, lon]);
      }
      let tsLabel = 'Onbekend tijdstip';
      if (d.timestamp) {
        const ms = d.timestamp > 1e12 ? d.timestamp : d.timestamp * 1000;
        tsLabel = new Date(ms).toLocaleString('nl-NL');
      }
      const srcLabel = d.source === 'live' ? 'Live positie' : 'Laatste rit';
      document.getElementById('loc-info').textContent =
        `${lat.toFixed(5)}, ${lon.toFixed(5)} — ${srcLabel}: ${tsLabel}`;
    } else {
      document.getElementById('loc-info').textContent =
        d.error || 'Geen locatiedata beschikbaar in trip history';
    }
  } catch (e) {
    document.getElementById('loc-info').textContent = 'Fout: ' + e;
  }
}

loadLocation();
</script>
</body>
</html>
"""


# ── Login Page HTML ───────────────────────────────────────────────────────────
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ZEEKR — Login</title>
<style>
  @font-face { font-family: 'ZeekrHeadline'; src: url('/static/ZeekrHeadline-Regular.woff2') format('woff2'); font-weight: 400; }
  @font-face { font-family: 'ZeekrText'; src: url('/static/ZeekrText-Regular.woff2') format('woff2'); font-weight: 400; }
  @font-face { font-family: 'ZeekrText'; src: url('/static/ZeekrText-Medium.woff2') format('woff2'); font-weight: 500; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'ZeekrText', -apple-system, 'Segoe UI', sans-serif;
    background: #0a0a0a;
    min-height: 100vh;
    display: flex; flex-direction: column;
    align-items: center; justify-content: center;
    padding: 24px;
    -webkit-font-smoothing: antialiased;
    background-image: url('/static/zeekr_x_hero_main.jpg');
    background-size: cover;
    background-position: center 40%;
    background-repeat: no-repeat;
  }
  .login-card {
    background: rgba(255,255,255,0.92);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border-radius: 24px;
    box-shadow: 0 8px 40px rgba(0,0,0,0.25);
    padding: 40px 32px;
    width: 100%; max-width: 400px;
    text-align: center;
  }
  .car-img { display: none; }
  .login-title {
    font-family: 'ZeekrHeadline', sans-serif;
    font-size: 22px; font-weight: 400;
    color: rgba(0,0,0,0.85);
    margin-bottom: 4px;
    letter-spacing: 0.3px;
  }
  .login-sub {
    font-size: 13px; color: rgba(0,0,0,0.4);
    margin-bottom: 28px;
  }
  .form-group {
    margin-bottom: 16px; text-align: left;
  }
  .form-label {
    font-size: 12px; font-weight: 500;
    color: rgba(0,0,0,0.5);
    margin-bottom: 6px; display: block;
    text-transform: uppercase; letter-spacing: 0.5px;
  }
  .form-input {
    width: 100%; padding: 12px 14px;
    border: 1.5px solid rgba(0,0,0,0.08);
    border-radius: 12px;
    font-family: 'ZeekrText', sans-serif;
    font-size: 15px; color: rgba(0,0,0,0.85);
    background: #F7F7F8;
    outline: none; transition: border-color 0.2s;
  }
  .form-input:focus { border-color: #ED8733; }
  .form-input::placeholder { color: rgba(0,0,0,0.25); }
  .login-btn {
    width: 100%; padding: 14px;
    background: #ED8733; color: #fff;
    border: none; border-radius: 14px;
    font-family: 'ZeekrText', sans-serif;
    font-size: 15px; font-weight: 500;
    cursor: pointer; transition: all 0.25s cubic-bezier(0.25, 0.46, 0.45, 0.94);
    margin-top: 8px;
    letter-spacing: 0.3px;
    box-shadow: 0 4px 16px rgba(237,135,51,0.3);
  }
  .login-btn:hover { background: #D97A2B; box-shadow: 0 6px 20px rgba(237,135,51,0.35); }
  .login-btn:active { transform: scale(0.97); box-shadow: 0 2px 8px rgba(237,135,51,0.2); }
  .login-btn:disabled { background: #ccc; cursor: not-allowed; box-shadow: none; }
  .error-msg {
    color: #FF3B30; font-size: 13px;
    margin-top: 12px; display: none;
  }
  .error-msg.show { display: block; }
  .footer {
    margin-top: 24px; font-size: 11px;
    color: rgba(255,255,255,0.5);
    text-shadow: 0 1px 4px rgba(0,0,0,0.5);
  }
</style>
</head>
<body>
<div class="login-card">
  <h1 class="login-title">Welcome to your ZEEKR</h1>
  <p class="login-sub">Log in met je Zeekr account</p>
  <form id="login-form" onsubmit="doLogin(event)">
    <div class="form-group">
      <label class="form-label">E-mailadres</label>
      <input class="form-input" type="email" id="email" placeholder="naam@voorbeeld.nl" required autofocus>
    </div>
    <div class="form-group">
      <label class="form-label">Wachtwoord</label>
      <input class="form-input" type="password" id="password" placeholder="Je Zeekr wachtwoord" required>
    </div>
    <div class="form-group">
      <label class="form-label">Land / Region</label>
      <select class="form-input" id="country">
        <option value="NL">Nederland</option>
        <option value="SE">Sverige (Sweden)</option>
        <option value="NO">Norge (Norway)</option>
        <option value="DE">Deutschland (Germany)</option>
        <option value="DK">Danmark (Denmark)</option>
        <option value="IL">Israel</option>
        <option value="AU">Australia</option>
        <option value="TH">Thailand</option>
        <option value="MY">Malaysia</option>
      </select>
    </div>
    <button class="login-btn" type="submit" id="login-btn">Inloggen</button>
    <div class="error-msg" id="error-msg"></div>
  </form>
</div>
<div class="footer">ZEEKR EV &mdash; Unofficial Dashboard</div>
<script>
async function doLogin(e) {
  e.preventDefault();
  const btn = document.getElementById('login-btn');
  const err = document.getElementById('error-msg');
  err.className = 'error-msg';
  btn.disabled = true; btn.textContent = 'Inloggen...';
  try {
    const res = await fetch('/api/login', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        email: document.getElementById('email').value,
        password: document.getElementById('password').value,
        country: document.getElementById('country').value,
      }),
    });
    const d = await res.json();
    if (d.ok) {
      window.location.href = '/widget';
    } else {
      err.textContent = d.error || 'Inloggen mislukt';
      err.className = 'error-msg show';
    }
  } catch (ex) {
    err.textContent = 'Verbindingsfout: ' + ex.message;
    err.className = 'error-msg show';
  }
  btn.disabled = false; btn.textContent = 'Inloggen';
}
</script>
</body>
</html>
"""


# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if _get_session(request):
        return RedirectResponse("/widget", status_code=302)
    return LOGIN_HTML


@app.post("/api/login")
async def api_login(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Ongeldige request"})
    email = body.get("email", "").strip()
    password = body.get("password", "")
    country = body.get("country", "NL").strip().upper()
    if not email or not password:
        return JSONResponse(status_code=400, content={"error": "Vul e-mail en wachtwoord in"})

    c = None
    # Try fresh login first
    try:
        c = ZeekrClient(username=email, password=password, country_code=country)
        c.login()
    except Exception as e:
        logger.warning(f"Fresh login mislukt voor {email}: {e}")
        c = None

    # Fallback: use cached session.json if credentials match
    if c is None:
        session_file = os.path.join(os.path.dirname(__file__), "session.json")
        try:
            if os.path.exists(session_file):
                with open(session_file, "r", encoding="utf-8") as f:
                    session_data = json.load(f)
                stored_email = session_data.get("username", "")
                stored_password = os.environ.get("ZEEKR_PASSWORD", "")
                if (stored_email.lower() == email.lower()
                        and stored_password == password
                        and session_data.get("bearer_token")):
                    c = ZeekrClient(session_data=session_data)
                    logger.info(f"Login via cached session voor {email}")
        except Exception as e:
            logger.warning(f"Session fallback mislukt: {e}")

    if c is None:
        return JSONResponse(status_code=401, content={"error": "Inloggen mislukt — controleer je gegevens"})

    token = _create_session(email, c)
    response = JSONResponse(content={"ok": True})
    response.set_cookie(
        SESSION_COOKIE, token,
        httponly=True, samesite="strict", secure=True, max_age=86400 * 30,
    )
    return response


@app.post("/api/logout")
async def api_logout(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    default_token = getattr(app.state, "default_session_token", None)
    # Only delete user-created sessions, never the default env session
    if token and token in sessions and token != default_token:
        del sessions[token]
    response = RedirectResponse("/", status_code=302)
    response.delete_cookie(SESSION_COOKIE)
    return response


@app.get("/api/vehicles")
async def api_vehicles(request: Request):
    """List vehicles for the current session."""
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    vehicles = sess.get("vehicles", [])
    return JSONResponse(content={
        "vehicles": [{"vin": v.vin, "model": v.data.get("modelName", ""), "name": v.data.get("vehicleName", "")} for v in vehicles],
        "active_vin": sess.get("active_vin"),
    })


@app.post("/api/vehicles/select")
async def api_vehicle_select(request: Request):
    """Switch active vehicle for the current session."""
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Ongeldige request"})
    vin = body.get("vin", "")
    vehicles = sess.get("vehicles", [])
    if not any(v.vin == vin for v in vehicles):
        return JSONResponse(status_code=404, content={"error": "Voertuig niet gevonden"})
    sess["active_vin"] = vin
    sess["cached_data"] = {}
    sess["cached_location"] = {}
    return JSONResponse(content={"ok": True, "active_vin": vin})


_NO_CACHE = {"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0", "Pragma": "no-cache"}


@app.get("/")
async def root(request: Request):
    sess = _get_session(request)
    if not sess:
        return RedirectResponse("/login", status_code=302)
    return RedirectResponse("/widget", status_code=302)


@app.get("/widget", response_class=HTMLResponse)
async def widget(request: Request):
    sess = _get_session(request)
    if not sess:
        return RedirectResponse("/login", status_code=302)
    widget_path = os.path.join(os.path.dirname(__file__), "static", "widget.html")
    with open(widget_path, encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), headers=_NO_CACHE)


@app.get("/configurator", response_class=HTMLResponse)
async def configurator(request: Request):
    sess = _get_session(request)
    if not sess:
        return RedirectResponse("/login", status_code=302)
    cfg_path = os.path.join(os.path.dirname(__file__), "static", "configurator.html")
    with open(cfg_path, encoding="utf-8") as f:
        return HTMLResponse(content=f.read(), headers=_NO_CACHE)


@app.get("/api/prefs")
async def api_get_prefs(request: Request):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    prefs = _load_prefs()
    user_prefs = prefs.get(sess["username"].lower(), {})
    return JSONResponse(content=user_prefs)


@app.post("/api/prefs")
async def api_set_prefs(request: Request):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(status_code=400, content={"error": "Ongeldige request"})
    if len(json.dumps(body)) > 10_000:
        return JSONResponse(status_code=400, content={"error": "Voorkeuren te groot (max 10KB)"})
    prefs = _load_prefs()
    prefs[sess["username"].lower()] = body
    _save_prefs(prefs)
    return JSONResponse(content={"ok": True})


@app.get("/api/status")
async def api_status(request: Request):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        data = fetch_vehicle_data(sess)
        return JSONResponse(content={
            **data,
            "_updated": sess["last_updated"].isoformat() if sess["last_updated"] else None,
        })
    except Exception as e:
        logger.error(f"API fout: {e}")
        return JSONResponse(status_code=500, content={"error": "Interne fout bij ophalen status"})


@app.get("/api/location")
async def api_location(request: Request):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        data = fetch_location_data(sess)
        return JSONResponse(content=data)
    except Exception as e:
        logger.error(f"Locatie fout: {e}")
        return JSONResponse(status_code=500, content={"error": "Interne fout bij ophalen locatie"})


@app.get("/api/calendar")
async def api_calendar(request: Request):
    """Fetch upcoming Google Calendar events with locations via gws CLI.
    Only available when gws CLI is installed on the host system."""
    import subprocess, json as _json, shutil
    gws_cmd = shutil.which("gws") or os.path.expanduser("~/AppData/Roaming/npm/gws.cmd")
    if not os.path.isfile(gws_cmd):
        return JSONResponse(status_code=404, content={"error": "Calendar niet beschikbaar (gws CLI niet geïnstalleerd)", "events": []})
    try:
        result = subprocess.run(
            [gws_cmd, "calendar", "+agenda", "--days", "3", "--format", "json"],
            capture_output=True, text=True, timeout=15, shell=False
        )
        if result.returncode != 0:
            logger.error(f"gws calendar error: {result.stderr}")
            return JSONResponse(content={"events": [], "error": "Calendar ophalen mislukt"})

        raw = _json.loads(result.stdout) if result.stdout.strip() else {}
        events = []
        items = raw.get("events", []) if isinstance(raw, dict) else raw
        for ev in items:
            location = ev.get("location", "") or ""
            # gws uses "False" string for empty locations
            if location.lower() == "false":
                location = ""
            summary = ev.get("summary", ev.get("title", ""))
            start_dt = ev.get("start", "")
            end_dt = ev.get("end", "")
            events.append({
                "summary": summary,
                "location": location,
                "start": start_dt,
                "end": end_dt,
                "has_location": bool(location and location.strip()),
            })
        return JSONResponse(content={"events": events})
    except subprocess.TimeoutExpired:
        return JSONResponse(content={"events": [], "error": "Calendar timeout"})
    except Exception as e:
        logger.error(f"Calendar fout: {e}")
        return JSONResponse(content={"events": [], "error": "Calendar ophalen mislukt"})



def _get_vehicle_from_session(sess: Dict[str, Any]):
    v = _get_active_vehicle(sess)
    if not v:
        raise Exception("Geen voertuigen gevonden")
    return v


@app.post("/api/control/{action}")
async def api_control(action: str, request: Request):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        body = await request.json()
    except Exception:
        body = {}
    try:
        v = _get_vehicle_from_session(sess)
        def _rc(cmd, sid, params):
            return v.do_remote_control(
                command=cmd, serviceID=sid,
                setting={"serviceParameters": params})

        def _preheat():
            temp = str(body.get("temperature", 22.0))
            dur = str(body.get("duration_min", 30))
            params = [
                {"key": "operation", "value": "4"},
                {"key": "AC", "value": "true"},
                {"key": "AC.temp", "value": temp},
                {"key": "AC.duration", "value": dur},
            ]
            if body.get("seat_heat_driver"):
                params.append({"key": "SH.driver", "value": "true"})
                params.append({"key": "SH.driver.level", "value": str(body.get("seat_heat_driver", 2))})
                params.append({"key": "SH.driver.duration", "value": dur})
            if body.get("seat_heat_passenger"):
                params.append({"key": "SH.passenger", "value": "true"})
                params.append({"key": "SH.passenger.level", "value": str(body.get("seat_heat_passenger", 2))})
                params.append({"key": "SH.passenger.duration", "value": dur})
            if body.get("steering_heat"):
                params.append({"key": "SW", "value": "true"})
                params.append({"key": "SW.level", "value": "2"})
                params.append({"key": "SW.duration", "value": dur})
            if body.get("rear_defrost"):
                params.append({"key": "RW", "value": "true"})
            result = _rc("start", "ZAF", params)
            if body.get("battery_precondition"):
                try:
                    from datetime import datetime, timedelta
                    now = datetime.now()
                    end = now + timedelta(minutes=int(dur))
                    v.set_charge_plan(
                        start_time=now.strftime("%H:%M"),
                        end_time=end.strftime("%H:%M"),
                        command="start",
                        bc_temp_active=True,
                    )
                except Exception as e:
                    logger.warning(f"Battery precondition failed: {e}")
            return result

        actions = {
            "lock": lambda: _rc("start", "RDL", [{"key": "door", "value": "all"}]),
            "unlock": lambda: _rc("stop", "RDU", [{"key": "door", "value": "all"}]),
            "find": lambda: v.find(),
            "trunk_open": lambda: _rc("stop", "RDU", [{"key": "target", "value": "trunk"}]),
            "trunk_close": lambda: _rc("start", "RDL", [{"key": "target", "value": "trunk"}]),
            "flash": lambda: _rc("start", "RHL", [{"key": "rhl", "value": "light-flash"}]),
            "horn": lambda: _rc("start", "RHL", [{"key": "rhl", "value": "horn"}]),
            "preheat": lambda: _preheat(),
            "stop_climate": lambda: _rc("start", "ZAF", [
                {"key": "AC", "value": "false"},
            ]),
            "defrost": lambda: _rc("start", "ZAF", [
                {"key": "DF", "value": "true"},
                {"key": "DF.level", "value": "2"},
                {"key": "RW", "value": "true"},
                {"key": "AC", "value": "true"},
            ]),
            "defrost_off": lambda: _rc("start", "ZAF", [
                {"key": "DF", "value": "false"},
                {"key": "RW", "value": "false"},
            ]),
            "defrost_front": lambda: _rc("start", "ZAF", [
                {"key": "DF", "value": "true" if body.get("enabled", True) else "false"},
                {"key": "DF.level", "value": "2"},
            ]),
            "defrost_rear": lambda: _rc("start", "ZAF", [
                {"key": "RW", "value": "true" if body.get("enabled", True) else "false"},
            ]),
            "seat_heating": lambda: _rc("start", "ZAF", [
                {"key": "SH.driver", "value": "true" if body.get("seat_fl", 0) > 0 else "false"},
                {"key": "SH.driver.level", "value": str(body.get("seat_fl", 0))},
                {"key": "SH.passenger", "value": "true" if body.get("seat_fr", 0) > 0 else "false"},
                {"key": "SH.passenger.level", "value": str(body.get("seat_fr", 0))},
            ]),
            "seat_ventilation": lambda: _rc("start", "ZAF", [
                {"key": "SV.driver", "value": "true" if body.get("seat_fl", 0) > 0 else "false"},
                {"key": "SV.driver.level", "value": str(body.get("seat_fl", 0))},
                {"key": "SV.passenger", "value": "true" if body.get("seat_fr", 0) > 0 else "false"},
                {"key": "SV.passenger.level", "value": str(body.get("seat_fr", 0))},
            ]),
            "steering_heating": lambda: _rc("start", "ZAF", [
                {"key": "SW", "value": "true" if body.get("level", 1) > 0 else "false"},
                {"key": "SW.level", "value": str(body.get("level", 1))},
            ]),
            "fan_speed": lambda: _rc("start", "ZAF", [
                {"key": "AC.fan", "value": str(body.get("level", 1))},
            ]),
            "ventilate_open": lambda: _rc("start", "RWS", [{"key": "target", "value": "ventilate"}]),
            "ventilate_close": lambda: _rc("stop", "RWS", [{"key": "target", "value": "ventilate"}]),
            "open_windows": lambda: _rc("start", "RWS", [{"key": "target", "value": "window"}]),
            "close_windows": lambda: _rc("stop", "RWS", [{"key": "target", "value": "window"}]),
            "start_charge": lambda: _rc("start", "RCS", [
                {"key": "rcs.restart", "value": "1"},
            ]),
            "stop_charge": lambda: _rc("stop", "RCS", [
                {"key": "rcs.terminate", "value": "1"},
            ]),
            "set_charge_limit": lambda: _rc("start", "RCS", [
                {"key": "rcs.setting", "value": "1"},
                {"key": "soc", "value": str(body.get("limit", 80))},
            ]),
            "sentry_on": lambda: _rc("start", "RSM", [{"key": "rsm", "value": "6"}]),
            "sentry_off": lambda: _rc("stop", "RSM", [{"key": "rsm", "value": "6"}]),
        }
        if action not in actions:
            return JSONResponse(status_code=400, content={
                "error": f"Onbekende actie: {action}",
                "available": list(actions.keys()),
            })
        logger.info(f"Control: {action} [{sess['username']}] body={body}")
        result = actions[action]()
        logger.info(f"Control result ({action}): {result}")
        ok = result is True or (isinstance(result, dict) and result.get("success"))
        return JSONResponse(content={"ok": ok, "action": action, "result": result})
    except Exception as e:
        logger.error(f"Control fout ({action}): {e}")
        return JSONResponse(status_code=500, content={"error": "Commando mislukt"})


def _format_trips(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Normalize raw trip list from Zeekr API."""
    trips = []
    items = raw.get("data", raw.get("list", []))
    if not isinstance(items, list):
        items = []
    for t in items:
        start_ms = t.get("startTime", 0)
        end_ms = t.get("endTime", 0)
        # Distance: traveledDistance or calculate from odometers
        dist = t.get("traveledDistance") or t.get("distance")
        if not dist:
            start_odo = t.get("startOdometer", 0) or 0
            end_odo = t.get("endOdometer", 0) or 0
            dist = end_odo - start_odo if end_odo > start_odo else 0
        dist = dist or 0
        energy_raw = t.get("electricConsumption", 0) or 0
        # electricConsumption is kWh/100km from the API
        per100 = round(energy_raw, 1)
        energy = round(energy_raw * dist / 100, 2) if dist > 0 else 0
        duration_s = (end_ms - start_ms) / 1000 if end_ms and start_ms else t.get("duration", 0)
        # Coordinates: from trackPoints if not in trip root
        track_pts = t.get("trackPoints") or t.get("trackPointList") or []
        start_lat = t.get("startLatitude")
        start_lng = t.get("startLongitude")
        end_lat = t.get("endLatitude")
        end_lng = t.get("endLongitude")
        if not start_lat and track_pts:
            start_lat = track_pts[0].get("latitude")
            start_lng = track_pts[0].get("longitude")
        if not end_lat and track_pts:
            end_lat = track_pts[-1].get("latitude")
            end_lng = track_pts[-1].get("longitude")
        trips.append({
            "tripId": t.get("tripId"),
            "reportTime": t.get("reportTime", start_ms),
            "date": datetime.fromtimestamp(start_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d") if start_ms else "",
            "start": datetime.fromtimestamp(start_ms / 1000, tz=timezone.utc).strftime("%H:%M") if start_ms else "",
            "end": datetime.fromtimestamp(end_ms / 1000, tz=timezone.utc).strftime("%H:%M") if end_ms else "",
            "distance_km": round(dist, 1),
            "duration_min": round(duration_s / 60, 1),
            "avg_speed_kmh": round(t.get("avgSpeed", 0), 1),
            "energy_kwh": round(energy, 2),
            "consumption_per_100km": per100,
            "start_mileage": round(t.get("startOdometer") or t.get("startMileage", 0), 1),
            "end_mileage": round(t.get("endOdometer") or t.get("endMileage", 0), 1),
            "start_lat": start_lat,
            "start_lng": start_lng,
            "end_lat": end_lat,
            "end_lng": end_lng,
        })
    return trips


@app.get("/api/trips")
async def api_trips(request: Request, days: int = 30, page: int = 1, size: int = 50):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        v = _get_vehicle_from_session(sess)
        fetch_days = days if days > 0 else 3650  # 0 = alles (~10 jaar)
        raw = v.get_journey_log(page_size=size, current_page=page, days_back=fetch_days)
        trips = _format_trips(raw)
        return JSONResponse(content={
            "total": raw.get("total", 0),
            "page": page,
            "trips": trips,
        })
    except Exception as e:
        logger.error(f"Trips fout: {e}")
        return JSONResponse(status_code=500, content={"error": "Interne fout bij ophalen ritten"})


@app.get("/api/trips/{trip_id}/trackpoints")
async def api_trip_trackpoints(request: Request, trip_id: int, report_time: int = 0):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        v = _get_vehicle_from_session(sess)
        raw = v.get_trip_trackpoints(report_time, trip_id)
        return JSONResponse(content=raw)
    except Exception as e:
        logger.error(f"Trackpoints fout: {e}")
        return JSONResponse(status_code=500, content={"error": "Interne fout bij ophalen trackpoints"})


@app.get("/api/trips/csv")
async def api_trips_csv(request: Request, days: int = 90, date_from: str = "", date_to: str = ""):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        v = _get_vehicle_from_session(sess)
        fetch_days = days if days > 0 else 3650
        raw = v.get_journey_log(page_size=200, current_page=1, days_back=fetch_days)
        trips = _format_trips(raw)
        if date_from:
            trips = [t for t in trips if t["date"] >= date_from and (not date_to or t["date"] <= date_to)]

        output = StringIO()
        writer = csv.writer(output, delimiter=";")
        writer.writerow(["Datum", "Start", "Eind", "Afstand (km)", "Duur (min)",
                         "Gem. snelheid (km/h)", "Verbruik (kWh)", "Verbruik (kWh/100km)",
                         "Km-stand start", "Km-stand eind"])
        for t in trips:
            writer.writerow([
                t["date"], t["start"], t["end"],
                t["distance_km"], t["duration_min"], t["avg_speed_kmh"],
                t["energy_kwh"], t["consumption_per_100km"], t["start_mileage"], t["end_mileage"],
            ])

        from starlette.responses import Response
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=zeekr_trips_{days}d.csv",
            },
        )
    except Exception as e:
        logger.error(f"Trips CSV fout: {e}")
        return JSONResponse(status_code=500, content={"error": "Interne fout bij CSV export"})


# ── Sentry endpoints ──────────────────────────────────────────────────────────

@app.get("/api/sentry/events")
async def api_sentry_events(request: Request):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        v = _get_vehicle_from_session(sess)
        raw = v.get_sentry_events()
        return JSONResponse(content=raw)
    except Exception as e:
        logger.error(f"Sentry events fout: {e}")
        return JSONResponse(status_code=500, content={"error": "Interne fout bij ophalen sentry events"})


@app.get("/api/sentry/pics")
async def api_sentry_pics(request: Request):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        v = _get_vehicle_from_session(sess)
        raw = v.get_sentry_pics()
        return JSONResponse(content=raw)
    except Exception as e:
        logger.error(f"Sentry pics fout: {e}")
        return JSONResponse(status_code=500, content={"error": "Interne fout bij ophalen sentry fotos"})


# ── Geofence endpoints ───────────────────────────────────────────────────────

@app.get("/api/fences")
async def api_fences(request: Request):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        v = _get_vehicle_from_session(sess)
        raw = v.get_fence_list()
        return JSONResponse(content=raw)
    except Exception as e:
        logger.error(f"Fences fout: {e}")
        return JSONResponse(status_code=500, content={"error": "Interne fout bij ophalen geofences"})


@app.post("/api/fences")
async def api_create_fence(request: Request):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        body = await request.json()
        v = _get_vehicle_from_session(sess)
        result = v.create_fence(
            name=body.get("name", "Zone"),
            lat=float(body["lat"]),
            lon=float(body["lon"]),
            radius=int(body.get("radius", 500)),
            notify_enter=body.get("notify_enter", True),
            notify_exit=body.get("notify_exit", True),
        )
        ok = result.get("success", False) if isinstance(result, dict) else bool(result)
        return JSONResponse(content={"ok": ok, "result": result})
    except Exception as e:
        logger.error(f"Fence aanmaken fout: {e}")
        return JSONResponse(status_code=500, content={"error": "Interne fout bij aanmaken geofence"})


@app.delete("/api/fences/{fence_id}")
async def api_delete_fence(fence_id: str, request: Request):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        v = _get_vehicle_from_session(sess)
        ok = v.delete_fence(fence_id)
        return JSONResponse(content={"ok": ok})
    except Exception as e:
        logger.error(f"Fence verwijderen fout: {e}")
        return JSONResponse(status_code=500, content={"error": "Interne fout bij verwijderen geofence"})


@app.post("/api/fences/{fence_id}/toggle")
async def api_toggle_fence(fence_id: str, request: Request):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        body = await request.json()
        v = _get_vehicle_from_session(sess)
        ok = v.enable_fence(fence_id, enabled=body.get("enabled", True))
        return JSONResponse(content={"ok": ok})
    except Exception as e:
        logger.error(f"Fence toggle fout: {e}")
        return JSONResponse(status_code=500, content={"error": "Interne fout bij toggle geofence"})


# ── Charge plan endpoints ────────────────────────────────────────────────────

@app.get("/api/charge-plan")
async def api_get_charge_plan(request: Request):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        v = _get_vehicle_from_session(sess)
        raw = v.get_charge_plan()
        return JSONResponse(content=raw)
    except Exception as e:
        logger.error(f"Charge plan ophalen fout: {e}")
        return JSONResponse(status_code=500, content={"error": "Interne fout bij ophalen laadplan"})


@app.post("/api/charge-plan")
async def api_set_charge_plan(request: Request):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        body = await request.json()
        v = _get_vehicle_from_session(sess)
        ok = v.set_charge_plan(
            start_time=body.get("start_time", "23:00"),
            end_time=body.get("end_time", "07:00"),
            command=body.get("command", "start"),
            bc_cycle_active=body.get("bc_cycle_active", False),
            bc_temp_active=body.get("bc_temp_active", False),
        )
        return JSONResponse(content={"ok": ok})
    except Exception as e:
        logger.error(f"Charge plan instellen fout: {e}")
        return JSONResponse(status_code=500, content={"error": "Interne fout bij instellen laadplan"})


# ── Travel plan endpoints ────────────────────────────────────────────────────

@app.get("/api/travel-plan")
async def api_get_travel_plan(request: Request):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        v = _get_vehicle_from_session(sess)
        raw = v.get_travel_plan()
        return JSONResponse(content=raw)
    except Exception as e:
        logger.error(f"Travel plan ophalen fout: {e}")
        return JSONResponse(status_code=500, content={"error": "Interne fout bij ophalen reisplan"})


@app.post("/api/travel-plan")
async def api_set_travel_plan(request: Request):
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    try:
        body = await request.json()
        v = _get_vehicle_from_session(sess)
        ok = v.set_travel_plan(
            command=body.get("command", "start"),
            start_time=body.get("start_time", ""),
            ac_preconditioning=body.get("ac", True),
            steering_wheel_heating=body.get("steering_wheel_heating", False),
        )
        return JSONResponse(content={"ok": ok})
    except Exception as e:
        logger.error(f"Travel plan instellen fout: {e}")
        return JSONResponse(status_code=500, content={"error": "Interne fout bij instellen reisplan"})


# ── Schedules ─────────────────────────────────────────────────────────────────

@app.get("/api/schedules")
async def api_schedules(request: Request):
    """Get all schedules for the current session."""
    token = request.cookies.get(SESSION_COOKIE)
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    # Find the actual token (could be default)
    if not token or token not in sessions:
        token = getattr(app.state, "default_session_token", None)
    user_sched = schedules.get(token, {})
    return JSONResponse(content={
        k: {kk: vv for kk, vv in v.items() if not kk.startswith("_")}
        for k, v in user_sched.items()
    })


@app.post("/api/schedules/{schedule_type}")
async def api_set_schedule(schedule_type: str, request: Request):
    """Set or update a schedule. Types: climate, charge."""
    token = request.cookies.get(SESSION_COOKIE)
    sess = _get_session(request)
    if not sess:
        return JSONResponse(status_code=401, content={"error": "Niet ingelogd"})
    if schedule_type not in ("climate", "charge"):
        return JSONResponse(status_code=400, content={"error": "Ongeldig type"})
    if not token or token not in sessions:
        token = getattr(app.state, "default_session_token", None)
    try:
        body = await request.json()
    except Exception:
        body = {}
    if token not in schedules:
        schedules[token] = {}
    sched = {
        "enabled": body.get("enabled", False),
        "time": body.get("time", "07:00"),
        "repeat": body.get("repeat", "daily"),
    }
    if schedule_type == "climate":
        sched.update({
            "mode": body.get("mode", "defrost"),
            "temperature": body.get("temperature", 22),
            "duration_min": body.get("duration_min", 15),
            "seat_heat_driver": body.get("seat_heat_driver", 0),
            "seat_heat_passenger": body.get("seat_heat_passenger", 0),
            "seat_vent_driver": body.get("seat_vent_driver", 0),
            "seat_vent_passenger": body.get("seat_vent_passenger", 0),
            "steering_heat": body.get("steering_heat", 0),
        })
    elif schedule_type == "charge":
        sched["time_from"] = body.get("time_from", body.get("time", "23:00"))
        sched["time_to"] = body.get("time_to", "07:00")
        sched["limit"] = body.get("limit", 80)
    schedules[token][schedule_type] = sched
    logger.info(f"Schedule {schedule_type} bijgewerkt: {schedules[token][schedule_type]} [{sess['username']}]")
    return JSONResponse(content={"ok": True, **{k: v for k, v in schedules[token][schedule_type].items() if not k.startswith("_")}})


if __name__ == "__main__":
    port = int(os.environ.get("ZEEKR_PORT", "3941"))
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="info")
