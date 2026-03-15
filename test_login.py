#!/usr/bin/env python3
"""Quick Zeekr API test — login + vehicle status dump."""

import json
import logging
import os
import sys

from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, "src")
from zeekr_ev_api.client import ZeekrClient

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

email = os.environ["ZEEKR_EMAIL"]
password = os.environ["ZEEKR_PASSWORD"]
country = os.environ.get("ZEEKR_COUNTRY", "NL")

print(f"Logging in as {email} (country: {country})...")
client = ZeekrClient(username=email, password=password, country_code=country)
client.login()
print("✅ Login success!")
print(f"   User info: {json.dumps(client.user_info, indent=2)}")

print("\nFetching vehicles...")
vehicles = client.get_vehicle_list()
if not vehicles:
    print("No vehicles found.")
    sys.exit(0)

for v in vehicles:
    print(f"\n🚗 VIN: {v.vin}")
    print(f"   Data: {json.dumps(v.data, indent=2)}")

    print("\n  📊 Vehicle status:")
    status = v.get_status()
    print(json.dumps(status, indent=2))

    print("\n  ⚡ Charging status:")
    charging = v.get_charging_status()
    print(json.dumps(charging, indent=2))

print("\nDone.")
