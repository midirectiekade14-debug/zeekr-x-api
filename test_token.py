#!/usr/bin/env python3
"""Test Zeekr API using captured Bearer token from logcat v2.9.9."""

import json
import logging
import sys

sys.path.insert(0, "src")
from zeekr_ev_api.client import ZeekrClient

logging.basicConfig(level=logging.DEBUG, format="%(levelname)s: %(message)s")

# Bearer token captured from logcat v2.9.9 (valid until 2026-03-10)
BEARER_TOKEN = "Bearer eyJraWQiOiIzMGI1MmNiYmUzNmM0OWI0OTk4NTc4ZDkzNzAwMzQwMCIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIwYzI0YTk1ZGZmMjE0NjQ3YmIxZjU4OTc4ODNmMTkyNSIsIm9wZW5JZCI6IjBjMjRhOTVkZmYyMTQ2NDdiYjFmNTg5Nzg4M2YxOTI1IiwiaXNzIjoiaHR0cHM6Ly9ldS1zbmMtYXBpLWd3LWlubmVyLnplZWtybGlmZS5jb20vYXV0aC1zZXJ2aWNlL2lubmVyL3YxL29hdXRoL2luZm8iLCJ0eXAiOiJCZWFyZXIiLCJ1c2VySWQiOiIyMTcwMDI1MyIsInNpZCI6IjUxYTAwMWI1LWM3MjgtNGY4OC1hYjk1LWU0ZDNlOWY2MDAyYyIsImF1ZCI6InVzZXJfY2VudGVyX2NsaWVudF9waG9uZSIsImFjciI6IjEiLCJuYmYiOjE3NzI1NTI0ODcsImF6cCI6InVzZXJfY2VudGVyX2NsaWVudF9waG9uZSIsInNjb3BlIjoiIiwiZXhwIjoxNzczMTU3Mjg3LCJzZXNzaW9uX3N0YXRlIjoiNTFhMDAxYjUtYzcyOC00Zjg4LWFiOTUtZTRkM2U5ZjYwMDJjIiwiaWF0IjoxNzcyNTUyNDg3LCJqdGkiOiI5OTUzOGIxOC0zYjE2LTRhNTUtODJiOS0wZmUwMGY3ZmY0NWEifQ.cOXkphmzLG_QsxLskGw9CT5jCr0crvoE1KG3Anu2hucreW8QC4lQ35M0C4pbmqmmTSvKf4YDsNUvICwjG-rGJrtuqmQWPZhSQaDmDTmrRQLlzwQfawk7C10nauCYntDx8DpiN0eYEocNqYhs1d5p54fzT6MzXW7UtcCm5fxbH_SIE3ltAWaaW0LqTp0lHF2KRG196Dgho4_vttgMcXN60vwYD0H8VoP73jCysGIO29LBipCbJQij9SFtYYjqX3Wn5Be8eB81SjJuMEyr6UQFHTV8IKMQmEixhYzBgGC-P1ys80oKeuC4nwAUDeqz5RhBf0ilNcsJQ9DCVDUeTjaQOg"

# Session data from logcat capture
session_data = {
    "username": "harm@maatwerkinterieurs.info",
    "country_code": "NL",
    "auth_token": None,
    "bearer_token": BEARER_TOKEN,
    "user_info": {"userId": "21700253"},
    "app_server_host": "https://gateway-pub-azure.zeekr.eu/overseas-app/",
    "usercenter_host": "https://gateway-pub-azure.zeekr.eu/zeekr-cuc-idaas/",
    "message_host": "https://gateway-pub-azure.zeekr.eu/eu-message-core/",
    "region_code": "EU",
    "region_login_server": "https://eu-snc-tsp-api-gw.zeekrlife.com/",
}

print("Loading session with captured Bearer token...")
client = ZeekrClient(session_data=session_data)
print(f"  Logged in: {client.logged_in}")
print(f"  Region: {client.region_code}")
print(f"  Login server: {client.region_login_server}")

print("\n--- Fetching vehicle list ---")
try:
    vehicles = client.get_vehicle_list()
    if not vehicles:
        print("No vehicles found.")
        sys.exit(0)
    for v in vehicles:
        print(f"\n  VIN: {v.vin}")
        print(f"  Data: {json.dumps(v.data, indent=2)}")

        print("\n  Vehicle status:")
        status = v.get_status()
        print(json.dumps(status, indent=2))

        print("\n  Charging status:")
        charging = v.get_charging_status()
        print(json.dumps(charging, indent=2))

    print("\nDone!")
except Exception as e:
    print(f"\nERROR: {e}")
    import traceback
    traceback.print_exc()
