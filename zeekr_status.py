#!/usr/bin/env python3
"""Zeekr EV status CLI — outputs JSON for dashboard integration."""

import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from zeekr_ev_api.client import ZeekrClient

SESSION_FILE = os.path.join(os.path.dirname(__file__), "..", "session.json")


def safe_float(val, default=None):
    """Safely convert to float, return default if not possible."""
    if val is None or val == "" or val == "None":
        return default
    try:
        return float(val)
    except (ValueError, TypeError):
        return default


def safe_int(val, default=None):
    """Safely convert to int."""
    f = safe_float(val)
    return round(f) if f is not None else default


def main():
    # Load session
    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as f:
            session_data = json.load(f)
    except Exception as e:
        print(json.dumps({"error": f"Session laden mislukt: {e}"}))
        sys.exit(0)

    # Init client
    try:
        client = ZeekrClient(session_data=session_data)
    except Exception as e:
        print(json.dumps({"error": f"Client init mislukt: {e}"}))
        sys.exit(0)

    # Fetch vehicle list
    try:
        vehicles = client.get_vehicle_list()
    except Exception as e:
        print(json.dumps({"error": f"Vehicle list mislukt: {e}"}))
        sys.exit(0)

    if not vehicles:
        print(json.dumps({"error": "Geen voertuigen gevonden"}))
        sys.exit(0)

    v = vehicles[0]

    # Fetch status
    try:
        status = v.get_status() or {}
    except Exception as e:
        status = {"error": str(e)}

    # Fetch charging
    try:
        charging = v.get_charging_status() or {}
    except Exception as e:
        charging = {"error": str(e)}

    # Extract from known Zeekr API structure
    basic = status.get("basicVehicleStatus", {})
    add = status.get("additionalVehicleStatus", {})
    ev = add.get("electricVehicleStatus", {})
    safety = add.get("drivingSafetyStatus", {})
    maintenance = add.get("maintenanceStatus", {})
    climate = add.get("climateStatus", {})
    running = add.get("runningStatus", {})
    pollution = add.get("pollutionStatus", {})
    position = basic.get("position", {})

    # === Battery & Range ===
    soc = safe_float(ev.get("chargeLevel") or ev.get("stateOfCharge"))
    soc = round(soc) if soc is not None and soc > 0 else None
    range_km = safe_int(ev.get("distanceToEmptyOnBatteryOnly"))
    range_20 = safe_int(ev.get("distanceToEmptyOnBattery20Soc"))
    range_100 = safe_int(ev.get("distanceToEmptyOnBattery100Soc"))
    avg_consumption = safe_float(ev.get("averPowerConsumption"))

    # === Odometer & Service ===
    odometer_km = safe_int(maintenance.get("odometer"))
    dist_service_km = safe_int(maintenance.get("distanceToService"))
    days_to_service = safe_int(maintenance.get("daysToService"))

    # === Lock & Doors ===
    lock_str = safety.get("centralLockingStatus")
    # 0=unlocked, 1=locked, 2=partially locked
    locked = lock_str not in ("0", "", None) if lock_str is not None and lock_str != "" else None

    def door_status(open_key, lock_key):
        open_val = safety.get(open_key)
        lock_val = safety.get(lock_key)
        return {
            "open": open_val not in ("0", "", None) if open_val else False,
            "locked": lock_val not in ("0", "", None) if lock_val else None,
        }

    doors = {
        "driverFront": door_status("doorOpenStatusDriver", "doorLockStatusDriver"),
        "passengerFront": door_status("doorOpenStatusPassenger", "doorLockStatusPassenger"),
        "driverRear": door_status("doorOpenStatusDriverRear", "doorLockStatusDriverRear"),
        "passengerRear": door_status("doorOpenStatusPassengerRear", "doorLockStatusPassengerRear"),
    }

    trunk_open = safety.get("trunkOpenStatus") not in ("0", "", None) if safety.get("trunkOpenStatus") else None
    trunk_locked = safety.get("trunkLockStatus") not in ("0", "", None) if safety.get("trunkLockStatus") else None
    hood_open = safety.get("engineHoodOpenStatus") not in ("0", "", None) if safety.get("engineHoodOpenStatus") else None

    # === Windows ===
    def win_status(key):
        val = climate.get(key)
        # winStatus: 0=fully open, 1=partially, 2=closed
        if val is None or val == "":
            return None
        return {"closed": str(val) == "2", "pos": safe_int(climate.get(key.replace("Status", "Pos")))}

    windows = {
        "driverFront": win_status("winStatusDriver"),
        "passengerFront": win_status("winStatusPassenger"),
        "driverRear": win_status("winStatusDriverRear"),
        "passengerRear": win_status("winStatusPassengerRear"),
    }

    # Sunroof
    sunroof_status = climate.get("sunroofOpenStatus")
    sunroof = {
        "closed": str(sunroof_status) == "1" if sunroof_status else None,
        "pos": safe_int(climate.get("sunroofPos")),
    }

    # === Charging ===
    is_charging = ev.get("isCharging", False)
    is_plugged = ev.get("isPluggedIn", False)
    charge_power = safe_float(charging.get("chargePower"), 0.0)
    charge_voltage = safe_float(charging.get("chargeVoltage"), 0.0)
    charge_current = safe_float(charging.get("chargeCurrent"), 0.0)
    charge_speed = safe_int(charging.get("chargeSpeed"))
    time_to_full_str = ev.get("timeToFullyCharged")
    time_to_full = safe_int(time_to_full_str) if time_to_full_str != "2047" else None
    charge_lid_ac = ev.get("chargeLidAcStatus")  # 1=open, 2=closed
    charge_lid_dc = ev.get("chargeLidDcAcStatus")  # 1=open, 2=closed
    charger_state = ev.get("chargerState")  # 3=disconnected

    # === Climate ===
    interior_temp = safe_float(climate.get("interiorTemp"))
    airco_active = climate.get("preClimateActive") is True
    defrost = str(climate.get("defrost")) == "1"
    steering_heat = climate.get("steerWhlHeatingSts")  # 1=on, 2=off
    seat_heat_driver = climate.get("drvHeatDetail")  # 1=on, 2=off
    seat_heat_pass = climate.get("passHeatingDetail")  # 1=on, 2=off
    seat_vent_driver = climate.get("drvVentSts")  # 1=on, 2=off
    overheat_protect = climate.get("climateOverHeatProActive")

    # === Location ===
    lat = safe_float(position.get("latitude"))
    lon = safe_float(position.get("longitude"))
    location = {"lat": lat, "lon": lon} if lat and lon else None

    # === Tyres ===
    tyres = {
        "driverFront": {"pressure": safe_float(maintenance.get("tyreStatusDriver")), "temp": safe_int(maintenance.get("tyreTempDriver")), "warning": str(maintenance.get("tyrePreWarningDriver", "0")) not in ("0", "", "None")},
        "passengerFront": {"pressure": safe_float(maintenance.get("tyreStatusPassenger")), "temp": safe_int(maintenance.get("tyreTempPassenger")), "warning": str(maintenance.get("tyrePreWarningPassenger", "0")) not in ("0", "", "None")},
        "driverRear": {"pressure": safe_float(maintenance.get("tyreStatusDriverRear")), "temp": safe_int(maintenance.get("tyreTempDriverRear")), "warning": str(maintenance.get("tyrePreWarningDriverRear", "0")) not in ("0", "", "None")},
        "passengerRear": {"pressure": safe_float(maintenance.get("tyreStatusPassengerRear")), "temp": safe_int(maintenance.get("tyreTempPassengerRear")), "warning": str(maintenance.get("tyrePreWarningPassengerRear", "0")) not in ("0", "", "None")},
    }
    # Convert kPa to bar (275 kPa ≈ 2.75 bar)
    for t in tyres.values():
        if t["pressure"]:
            t["pressure_bar"] = round(t["pressure"] / 100, 2)

    # === 12V Battery ===
    main_batt = maintenance.get("mainBatteryStatus", {})
    battery_12v = safe_float(main_batt.get("voltage")) if main_batt else None

    # === Air Quality ===
    pm25 = safe_int(pollution.get("interiorPM25Level"))

    # === Engine / Mode ===
    engine = basic.get("engineStatus")
    car_mode = basic.get("carMode")
    speed = safe_float(basic.get("speed"))

    # === Fragrance System ===
    frag = climate.get("fragStrs", {})
    fragrance_active = frag.get("activated") == 1 if frag else None

    output = {
        "vin": v.vin,
        "plate": v.data.get("plateNo", ""),
        "model": v.data.get("modelName") or v.data.get("vehicleModelName") or "Zeekr X",

        # Battery
        "soc": soc,
        "range_km": range_km,
        "range_20_soc_km": range_20,
        "range_100_soc_km": range_100,
        "avg_consumption_kwh": avg_consumption,

        # Odometer & Service
        "odometer_km": odometer_km,
        "dist_service_km": dist_service_km,
        "days_to_service": days_to_service,

        # Lock & Security
        "locked": locked,
        "doors": doors,
        "trunk_open": trunk_open,
        "trunk_locked": trunk_locked,
        "hood_open": hood_open,

        # Windows & Sunroof
        "windows": windows,
        "sunroof": sunroof,

        # Charging
        "is_charging": is_charging,
        "is_plugged": is_plugged,
        "charge_power_kw": round(charge_power, 1),
        "charge_voltage": charge_voltage,
        "charge_current": charge_current,
        "charge_speed": charge_speed,
        "time_to_full_min": time_to_full,
        "charge_lid_ac": charge_lid_ac,
        "charge_lid_dc": charge_lid_dc,

        # Climate
        "interior_temp": interior_temp,
        "airco_active": airco_active,
        "defrost": defrost,
        # Climate controls: 1=on, 2=off (Zeekr convention)
        "steering_heat": str(steering_heat) == "1",
        "seat_heat_driver": str(seat_heat_driver) == "1",
        "seat_heat_passenger": str(seat_heat_pass) == "1",
        "seat_vent_driver": str(seat_vent_driver) == "1",
        "overheat_protect": overheat_protect,
        "fragrance_active": fragrance_active,

        # Tyres
        "tyres": tyres,

        # 12V & Air Quality
        "battery_12v": battery_12v,
        "pm25_interior": pm25,

        # Engine & Drive
        "engine": engine,
        "speed": speed,

        # Location
        "location": location,

        "timestamp": int(time.time() * 1000),
    }

    print(json.dumps(output, ensure_ascii=False))


if __name__ == "__main__":
    main()
