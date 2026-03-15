#!/usr/bin/env python3
"""Zeekr EV trip history CLI — fetch trips and trackpoints."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from zeekr_ev_api.client import ZeekrClient

SESSION_FILE = os.path.join(os.path.dirname(__file__), "..", "session.json")


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Gebruik: zeekr_trips.py <list|track> [args]"}))
        sys.exit(0)

    action = sys.argv[1].lower()

    # Load session
    try:
        with open(SESSION_FILE, "r", encoding="utf-8") as f:
            session_data = json.load(f)
    except Exception as e:
        print(json.dumps({"error": f"Session laden mislukt: {e}"}))
        sys.exit(0)

    try:
        client = ZeekrClient(session_data=session_data)
    except Exception as e:
        print(json.dumps({"error": f"Client init mislukt: {e}"}))
        sys.exit(0)

    try:
        vehicles = client.get_vehicle_list()
    except Exception as e:
        print(json.dumps({"error": f"Vehicle list mislukt: {e}"}))
        sys.exit(0)

    if not vehicles:
        print(json.dumps({"error": "Geen voertuigen gevonden"}))
        sys.exit(0)

    v = vehicles[0]

    if action == "list":
        days = int(sys.argv[2]) if len(sys.argv) > 2 else 30
        page = int(sys.argv[3]) if len(sys.argv) > 3 else 1
        size = int(sys.argv[4]) if len(sys.argv) > 4 else 20

        try:
            data = v.get_journey_log(page_size=size, current_page=page, days_back=days)
            print(json.dumps(data, ensure_ascii=False))
        except Exception as e:
            print(json.dumps({"error": str(e)}))

    elif action == "track":
        if len(sys.argv) < 4:
            print(json.dumps({"error": "Gebruik: zeekr_trips.py track <trip_id> <report_time>"}))
            sys.exit(0)

        trip_id = int(sys.argv[2])
        report_time = int(sys.argv[3])

        try:
            data = v.get_trip_trackpoints(trip_report_time=report_time, trip_id=trip_id)
            print(json.dumps(data, ensure_ascii=False))
        except Exception as e:
            print(json.dumps({"error": str(e)}))

    else:
        print(json.dumps({"error": f"Onbekend commando: {action}"}))


if __name__ == "__main__":
    main()
