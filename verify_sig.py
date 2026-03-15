#!/usr/bin/env python3
"""Verify X-SIGNATURE calculation against logcat capture to find the correct key."""

import base64
import hashlib
import hmac
import json
import sys

sys.path.insert(0, "src")
from zeekr_ev_api.zeekr_app_sig import calculate_sig, ALLOWED_HEADERS, validate_header
from requests import Request, PreparedRequest

# Known request from logcat v2.9.9 (line 8-24)
# GET https://eu-snc-tsp-api-gw.zeekrlife.com/ms-app-bff/api/v4.0/veh/vehicle-list?needSharedCar=true
EXPECTED_SIGNATURE = "FaHyBraTD09drIvZpDNIvnc357Wb61ddiEEueNm0i5I="

# Exact headers from logcat (order doesn't matter, they get sorted)
headers = {
    "X-APP-OS-VERSION": "",
    "X-APP-ID": "ZEEKRCNCH001M0001",
    "X-PROJECT-ID": "ZEEKR_EU",
    "Content-Type": "application/json; charset=UTF-8",
    "AppId": "ONEX97FB91F061405",
    "X-API-SIGNATURE-VERSION": "2.0",
    "X-P": "Android",
    "ACCEPT-LANGUAGE": "nl-NL",
    "X-API-SIGNATURE-NONCE": "30e41ad3-3896-42b2-abd0-9fd32ce9e6a8",
    "X-TIMESTAMP": "1772552487861",
    "X-DEVICE-ID": "581cbc60-ac8d-4bb1-b8e9-960d6fbc3b6b",
    "X-PLATFORM": "APP",
    "Authorization": "Bearer eyJraWQiOiIzMGI1MmNiYmUzNmM0OWI0OTk4NTc4ZDkzNzAwMzQwMCIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiIwYzI0YTk1ZGZmMjE0NjQ3YmIxZjU4OTc4ODNmMTkyNSIsIm9wZW5JZCI6IjBjMjRhOTVkZmYyMTQ2NDdiYjFmNTg5Nzg4M2YxOTI1IiwiaXNzIjoiaHR0cHM6Ly9ldS1zbmMtYXBpLWd3LWlubmVyLnplZWtybGlmZS5jb20vYXV0aC1zZXJ2aWNlL2lubmVyL3YxL29hdXRoL2luZm8iLCJ0eXAiOiJCZWFyZXIiLCJ1c2VySWQiOiIyMTcwMDI1MyIsInNpZCI6IjUxYTAwMWI1LWM3MjgtNGY4OC1hYjk1LWU0ZDNlOWY2MDAyYyIsImF1ZCI6InVzZXJfY2VudGVyX2NsaWVudF9waG9uZSIsImFjciI6IjEiLCJuYmYiOjE3NzI1NTI0ODcsImF6cCI6InVzZXJfY2VudGVyX2NsaWVudF9waG9uZSIsInNjb3BlIjoiIiwiZXhwIjoxNzczMTU3Mjg3LCJzZXNzaW9uX3N0YXRlIjoiNTFhMDAxYjUtYzcyOC00Zjg4LWFiOTUtZTRkM2U5ZjYwMDJjIiwiaWF0IjoxNzcyNTUyNDg3LCJqdGkiOiI5OTUzOGIxOC0zYjE2LTRhNTUtODJiOS0wZmUwMGY3ZmY0NWEifQ.cOXkphmzLG_QsxLskGw9CT5jCr0crvoE1KG3Anu2hucreW8QC4lQ35M0C4pbmqmmTSvKf4YDsNUvICwjG-rGJrtuqmQWPZhSQaDmDTmrRQLlzwQfawk7C10nauCYntDx8DpiN0eYEocNqYhs1d5p54fzT6MzXW7UtcCm5fxbH_SIE3ltAWaaW0LqTp0lHF2KRG196Dgho4_vttgMcXN60vwYD0H8VoP73jCysGIO29LBipCbJQij9SFtYYjqX3Wn5Be8eB81SjJuMEyr6UQFHTV8IKMQmEixhYzBgGC-P1ys80oKeuC4nwAUDeqz5RhBf0ilNcsJQ9DCVDUeTjaQOg",
    "X-VIN": "sdjw0wRnMkvTOpxWF5gHSrnszPm63NQbcLZNu/DvcsM=",
}

# Build a PreparedRequest matching the logcat data
req = Request("GET", "https://eu-snc-tsp-api-gw.zeekrlife.com/ms-app-bff/api/v4.0/veh/vehicle-list?needSharedCar=true", headers=headers)
prepped = req.prepare()

# Keys to test
keys = {
    "libHttpSecretKey (PROD_SECRET)": "c6163310f263911af87194dd290247fd",
    "libAppSecret (HMAC_SECRET)": "b816ffc222a657bef362d874a60337de",
    "zeekr_tis (appsecret)": "zeekr_tis",
}

print(f"Expected signature: {EXPECTED_SIGNATURE}")
print()

# First, show what headers are included in the signature
print("Headers included in signature (after filtering):")
for k, v in sorted(prepped.headers.items(), key=lambda x: x[0].lower()):
    if validate_header(k, v):
        print(f"  {k.lower()}: {v}")
print()

# Try each key
for name, key in keys.items():
    sig = calculate_sig(prepped, key)
    match = "MATCH!" if sig == EXPECTED_SIGNATURE else "no match"
    print(f"  {name}: {sig} [{match}]")

# Also try the second logcat request (POST to heartbeat) for validation
print("\n--- Second request validation (POST heartbeat) ---")
EXPECTED_SIG2 = "fayDsDSzN6tYVNbWYJkvVlLVx7ReDYCJ18xZYULXiTU="
headers2 = headers.copy()
headers2["X-API-SIGNATURE-NONCE"] = "5a784332-b587-4e17-a0ff-946ffa86356d"
headers2["X-TIMESTAMP"] = "1772552488105"
body2 = '{"deviceId":"581cbc60-ac8d-4bb1-b8e9-960d6fbc3b6b","deviceType":1,"hbType":1,"ts":1772552488103,"vin":"L6TBX2032PF504214"}'

req2 = Request("POST", "https://eu-snc-tsp-api-gw.zeekrlife.com/ms-app-online-manager/api/v1.0/app/hb", headers=headers2, data=body2)
prepped2 = req2.prepare()
# Fix content-type since prepare() might change it
prepped2.headers["Content-Type"] = "application/json; charset=UTF-8"

print(f"Expected: {EXPECTED_SIG2}")
for name, key in keys.items():
    sig = calculate_sig(prepped2, key)
    match = "MATCH!" if sig == EXPECTED_SIG2 else "no match"
    print(f"  {name}: {sig} [{match}]")
