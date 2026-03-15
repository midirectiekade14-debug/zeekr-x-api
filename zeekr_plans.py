#!/usr/bin/env python3
"""Zeekr EV charge/travel plan CLI — fetch and set plans."""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))
from zeekr_ev_api.client import ZeekrClient

SESSION_FILE = os.path.join(os.path.dirname(__file__), "..", "session.json")


def main():
    if len(sys.argv) < 2:
        print(json.dumps({"error": "Gebruik: zeekr_plans.py <charge-plan|set-charge-plan|travel-plan|set-travel-plan|charging-limit> [args]"}))
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

    if action == "charge-plan":
        try:
            data = v.get_charge_plan()
            print(json.dumps(data, ensure_ascii=False))
        except Exception as e:
            print(json.dumps({"error": str(e)}))

    elif action == "set-charge-plan":
        # args: start_time end_time [command]
        if len(sys.argv) < 4:
            print(json.dumps({"error": "Gebruik: zeekr_plans.py set-charge-plan <start_time> <end_time> [start|stop]"}))
            sys.exit(0)
        start_time = sys.argv[2]
        end_time = sys.argv[3]
        command = sys.argv[4] if len(sys.argv) > 4 else "start"
        try:
            success = v.set_charge_plan(start_time=start_time, end_time=end_time, command=command)
            print(json.dumps({"success": success}))
        except Exception as e:
            print(json.dumps({"error": str(e)}))

    elif action == "travel-plan":
        try:
            data = v.get_travel_plan()
            print(json.dumps(data, ensure_ascii=False))
        except Exception as e:
            print(json.dumps({"error": str(e)}))

    elif action == "set-travel-plan":
        # args: command [start_time] [ac] [steering_heat]
        command = sys.argv[2] if len(sys.argv) > 2 else "start"
        start_time = sys.argv[3] if len(sys.argv) > 3 else ""
        ac = sys.argv[4].lower() in ("true", "1", "yes") if len(sys.argv) > 4 else True
        steer = sys.argv[5].lower() in ("true", "1", "yes") if len(sys.argv) > 5 else False
        try:
            success = v.set_travel_plan(
                command=command,
                start_time=start_time,
                ac_preconditioning=ac,
                steering_wheel_heating=steer,
            )
            print(json.dumps({"success": success}))
        except Exception as e:
            print(json.dumps({"error": str(e)}))

    elif action == "charging-limit":
        try:
            data = v.get_charging_limit()
            print(json.dumps(data, ensure_ascii=False))
        except Exception as e:
            print(json.dumps({"error": str(e)}))

    else:
        print(json.dumps({"error": f"Onbekend commando: {action}"}))


if __name__ == "__main__":
    main()
