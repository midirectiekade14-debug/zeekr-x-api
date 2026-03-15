#!/usr/bin/env python3
"""Zeekr EV geo-fence and sentry CLI."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from zeekr_ev_api.client import ZeekrClient

SESSION_FILE = os.path.join(os.path.dirname(__file__), "..", "session.json")


def get_vehicle():
    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as f:
            session_data = json.load(f)
    except Exception as e:
        print(json.dumps({"error": f"Session laden mislukt: {e}"}))
        sys.exit(0)

    try:
        client = ZeekrClient(session_data=session_data)
        vehicles = client.get_vehicle_list()
    except Exception as e:
        print(json.dumps({"error": str(e)}))
        sys.exit(0)

    if not vehicles:
        print(json.dumps({"error": "Geen voertuigen gevonden"}))
        sys.exit(0)

    return vehicles[0]


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Gebruik: zeekr_fence.py <list|create|delete|enable|disable|sentry-events|sentry-pics>"}))
        sys.exit(0)

    action = sys.argv[1].lower()
    v = get_vehicle()

    try:
        if action == "list":
            data = v.get_fence_list()
            print(json.dumps(data, ensure_ascii=False))

        elif action == "create":
            if len(sys.argv) < 6:
                print(json.dumps({"error": "Gebruik: create <name> <lat> <lon> [radius]"}))
                sys.exit(0)
            name = sys.argv[2]
            lat = float(sys.argv[3])
            lon = float(sys.argv[4])
            radius = int(sys.argv[5]) if len(sys.argv) > 5 else 500
            data = v.create_fence(name=name, lat=lat, lon=lon, radius=radius)
            print(json.dumps(data, ensure_ascii=False))

        elif action == "delete":
            if len(sys.argv) < 3:
                print(json.dumps({"error": "Gebruik: delete <fence_id>"}))
                sys.exit(0)
            success = v.delete_fence(sys.argv[2])
            print(json.dumps({"success": success}))

        elif action in ("enable", "disable"):
            if len(sys.argv) < 3:
                print(json.dumps({"error": f"Gebruik: {action} <fence_id>"}))
                sys.exit(0)
            success = v.enable_fence(sys.argv[2], enabled=(action == "enable"))
            print(json.dumps({"success": success}))

        elif action == "sentry-events":
            data = v.get_sentry_events()
            print(json.dumps(data, ensure_ascii=False))

        elif action == "sentry-pics":
            data = v.get_sentry_pics()
            print(json.dumps(data, ensure_ascii=False))

        else:
            print(json.dumps({"error": f"Onbekend commando: {action}"}))

    except Exception as e:
        print(json.dumps({"error": str(e)}))


if __name__ == "__main__":
    main()
