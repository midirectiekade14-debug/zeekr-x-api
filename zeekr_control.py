#!/usr/bin/env python3
"""Zeekr EV remote control CLI — execute commands via API."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from zeekr_ev_api.client import ZeekrClient

SESSION_FILE = os.path.join(os.path.dirname(__file__), "..", "session.json")

# Remote control command definitions (new serviceParameters format, March 2026)
# Confirmed from Fryyyyy/zeekr_homeassistant HA integration
COMMANDS = {
    "lock": {
        "command": "start",
        "serviceId": "RDL",
        "setting": {"serviceParameters": [{"key": "door", "value": "all"}]},
    },
    "unlock": {
        "command": "stop",
        "serviceId": "RDU",
        "setting": {"serviceParameters": [{"key": "door", "value": "all"}]},
    },
    "flash": {
        "command": "start",
        "serviceId": "RHL",
        "setting": {"serviceParameters": [{"key": "rhl", "value": "light-flash"}]},
    },
    "horn": {
        "command": "start",
        "serviceId": "RHO",
        "setting": {"serviceParameters": [{"key": "rho", "value": "horn"}]},
    },
    "horn_flash": {
        "command": "start",
        "serviceId": "RHHF",
        "setting": {"serviceParameters": [{"key": "rhhf", "value": "horn-flash"}]},
    },
    "hvac_on": {
        "command": "start",
        "serviceId": "ZAF",
        "setting": {"serviceParameters": [
            {"key": "AC", "value": "true"},
            {"key": "AC.temp", "value": "21.0"},
            {"key": "AC.duration", "value": "15"},
        ]},
    },
    "hvac_off": {
        "command": "start",
        "serviceId": "ZAF",
        "setting": {"serviceParameters": [{"key": "AC", "value": "false"}]},
    },
    "trunk_open": {
        "command": "start",
        "serviceId": "RTG",
        "setting": {"serviceParameters": [{"key": "target", "value": "trunk"}]},
    },
    "trunk_close": {
        "command": "stop",
        "serviceId": "RTG",
        "setting": {"serviceParameters": [{"key": "target", "value": "trunk"}]},
    },
    "defrost_on": {
        "command": "start",
        "serviceId": "ZAF",
        "setting": {"serviceParameters": [
            {"key": "DF", "value": "true"},
            {"key": "DF.level", "value": "2"},
        ]},
    },
    "defrost_off": {
        "command": "start",
        "serviceId": "ZAF",
        "setting": {"serviceParameters": [{"key": "DF", "value": "false"}]},
    },
    "seat_heat_driver_on": {
        "command": "start",
        "serviceId": "ZAF",
        "setting": {"serviceParameters": [
            {"key": "SH.driver", "value": "true"},
            {"key": "SH.driver.level", "value": "3"},
        ]},
    },
    "seat_heat_driver_off": {
        "command": "start",
        "serviceId": "ZAF",
        "setting": {"serviceParameters": [{"key": "SH.driver", "value": "false"}]},
    },
    "charge_start": {
        "command": "start",
        "serviceId": "RCS",
        "setting": {"serviceParameters": [{"key": "rcs.restart", "value": "1"}]},
    },
    "charge_stop": {
        "command": "stop",
        "serviceId": "RCS",
        "setting": {"serviceParameters": [{"key": "rcs.terminate", "value": "1"}]},
    },
}


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Gebruik: zeekr_control.py <command>", "commands": list(COMMANDS.keys())}))
        sys.exit(0)

    action = sys.argv[1].lower()

    if action == "list":
        print(json.dumps({"commands": list(COMMANDS.keys())}))
        sys.exit(0)

    if action not in COMMANDS:
        print(json.dumps({"error": f"Onbekend commando: {action}", "commands": list(COMMANDS.keys())}))
        sys.exit(0)

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

    # Get vehicle
    try:
        vehicles = client.get_vehicle_list()
    except Exception as e:
        print(json.dumps({"error": f"Vehicle list mislukt: {e}"}))
        sys.exit(0)

    if not vehicles:
        print(json.dumps({"error": "Geen voertuigen gevonden"}))
        sys.exit(0)

    v = vehicles[0]
    cmd = COMMANDS[action]

    try:
        success = v.do_remote_control(
            command=cmd["command"],
            serviceID=cmd["serviceId"],
            setting=cmd["setting"],
        )
        print(json.dumps({
            "success": success,
            "action": action,
            "vin": v.vin,
        }))
    except Exception as e:
        print(json.dumps({"error": str(e), "action": action}))


if __name__ == "__main__":
    main()
