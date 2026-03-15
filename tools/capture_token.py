#!/usr/bin/env python3
"""
Zeekr Token Capture Tool
=========================
Captures a Bearer token from a running Zeekr app via ADB + logcat.
No root, no MITM proxy, no Frida required.

Requirements:
    - ADB installed and phone connected via USB
    - Zeekr app installed on the phone (com.zeekr.overseas or com.zeekr.global)
    - USB debugging enabled on the phone

Usage:
    python tools/capture_token.py [--device SERIAL] [--output session.json]

How it works:
    1. Clears app data to force a fresh login
    2. Relaunches the Zeekr app
    3. Automates the login flow via ADB input commands
    4. Captures the Bearer token and refresh token from logcat (OkHttp logs)
    5. Saves a session.json ready for the dashboard
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time


PACKAGE_NAMES = ["com.zeekr.overseas", "com.zeekr.global"]


def adb(*args, device=None):
    """Run an ADB command and return stdout."""
    cmd = ["adb"]
    if device:
        cmd += ["-s", device]
    cmd += list(args)
    env = os.environ.copy()
    env["MSYS_NO_PATHCONV"] = "1"
    result = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)
    return result.stdout.strip()


def adb_shell(*args, device=None):
    """Run an ADB shell command."""
    return adb("shell", *args, device=device)


def find_package(device=None):
    """Find which Zeekr package is installed."""
    packages = adb_shell("pm", "list", "packages", "-3", device=device)
    for pkg in PACKAGE_NAMES:
        if pkg in packages:
            return pkg
    return None


def get_logcat(device=None, filter_pattern=None):
    """Get logcat output, optionally filtered."""
    lines = adb("logcat", "-d", device=device).split("\n")
    if filter_pattern:
        pat = re.compile(filter_pattern, re.IGNORECASE)
        lines = [l for l in lines if pat.search(l)]
    return lines


def extract_token_from_logcat(device=None):
    """Parse logcat for Bearer token and login response."""
    lines = adb("logcat", "-d", device=device).split("\n")

    bearer_token = None
    refresh_token = None
    user_id = None
    open_id = None
    login_server = None

    for line in lines:
        # Capture the login response JSON
        if '"accessToken"' in line and '"refreshToken"' in line:
            try:
                json_start = line.index("{")
                data = json.loads(line[json_start:])
                if data.get("success"):
                    token_data = data.get("data", {})
                    bearer_token = token_data.get("accessToken", "")
                    refresh_token = token_data.get("refreshToken", "")
                    user_id = token_data.get("userId", "")
                    open_id = token_data.get("openId", "")
            except (json.JSONDecodeError, ValueError):
                pass

        # Capture the login server URL
        if "ms-user-auth" in line and "auth/login" in line and "-->" in line:
            match = re.search(r"https://([^/]+)/", line)
            if match:
                login_server = match.group(1)

        # Also try to capture from Authorization header
        if "Authorization: Bearer " in line and not bearer_token:
            match = re.search(r"Authorization: Bearer (\S+)", line)
            if match:
                bearer_token = "Bearer " + match.group(1)

    if bearer_token and not bearer_token.startswith("Bearer "):
        bearer_token = "Bearer " + bearer_token if bearer_token else None

    return {
        "bearer_token": bearer_token,
        "refresh_token": refresh_token,
        "user_id": user_id,
        "open_id": open_id,
        "login_server": login_server,
    }


def detect_region(login_server):
    """Detect region from login server hostname."""
    if not login_server:
        return "EU", {
            "app": "https://eu-snc-tsp-api-gw.zeekrlife.com/overseas-app/",
            "user": "https://eu-snc-tsp-api-gw.zeekrlife.com/zeekr-cuc-idaas/",
            "msg": "https://eu-snc-tsp-api-gw.zeekrlife.com/eu-message-core/",
            "login": f"https://{login_server}/",
        }

    base = f"https://{login_server}"
    if "eu" in login_server.lower():
        return "EU", {
            "app": f"{base}/overseas-app/",
            "user": f"{base}/zeekr-cuc-idaas/",
            "msg": f"{base}/eu-message-core/",
            "login": f"{base}/",
        }
    elif "em-sg" in login_server.lower() or "sea" in login_server.lower():
        return "SEA", {
            "app": f"{base}/overseas-app/",
            "user": f"{base}/zeekr-cuc-idaas-sea/",
            "msg": f"{base}/sea-message-core/",
            "login": f"{base}/",
        }
    else:
        return "EM", {
            "app": f"{base}/overseas-app/",
            "user": f"{base}/zeekr-cuc-idaas/",
            "msg": f"{base}/message-core/",
            "login": f"{base}/",
        }


def build_session(token_data, email):
    """Build a session.json from captured token data."""
    region, urls = detect_region(token_data["login_server"])

    return {
        "username": email,
        "country_code": "",
        "auth_token": None,
        "bearer_token": token_data["bearer_token"],
        "refresh_token": token_data["refresh_token"],
        "user_info": {
            "userId": token_data.get("user_id", ""),
            "openId": token_data.get("open_id", ""),
        },
        "app_server_host": urls["app"],
        "usercenter_host": urls["user"],
        "message_host": urls["msg"],
        "region_code": region,
        "region_login_server": urls["login"],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Capture Zeekr Bearer token via ADB logcat",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --email you@example.com
  %(prog)s --email you@example.com --output session.json
  %(prog)s --email you@example.com --device 4C081FDAP0014P
  %(prog)s --logcat-only   # Just parse existing logcat (no app restart)
        """,
    )
    parser.add_argument("--email", help="Your Zeekr account email")
    parser.add_argument("--device", "-s", help="ADB device serial (if multiple)")
    parser.add_argument("--output", "-o", default="session.json",
                        help="Output file (default: session.json)")
    parser.add_argument("--logcat-only", action="store_true",
                        help="Only parse existing logcat, don't restart app")

    args = parser.parse_args()

    # Check ADB
    try:
        devices = adb("devices")
        if "device" not in devices:
            print("ERROR: No ADB devices found. Connect your phone via USB.")
            sys.exit(1)
    except FileNotFoundError:
        print("ERROR: ADB not found. Install Android SDK Platform Tools.")
        sys.exit(1)

    # Find package
    pkg = find_package(device=args.device)
    if not pkg:
        print("ERROR: Zeekr app not installed on device.")
        sys.exit(1)
    print(f"[*] Found: {pkg}")

    if not args.logcat_only:
        if not args.email:
            print("ERROR: --email is required (unless using --logcat-only)")
            sys.exit(1)

        print("[*] Clearing app data...")
        adb_shell("pm", "clear", pkg, device=args.device)
        time.sleep(1)

        print("[*] Clearing logcat...")
        adb("logcat", "-c", device=args.device)

        print("[*] Launching Zeekr app...")
        adb_shell("monkey", "-p", pkg, "-c",
                   "android.intent.category.LAUNCHER", "1", device=args.device)
        print("[*] Waiting for app to load (8 sec)...")
        time.sleep(8)

        print(f"[*] Please log in manually on your phone with: {args.email}")
        print("[*] Waiting for login to complete...")

        # Poll logcat for up to 120 seconds
        for i in range(24):
            time.sleep(5)
            token_data = extract_token_from_logcat(device=args.device)
            if token_data["bearer_token"]:
                print("[*] Token captured!")
                break
            print(f"    ... waiting ({(i+1)*5}s)")
        else:
            print("[!] Timeout waiting for login. Try --logcat-only after manual login.")
            sys.exit(1)
    else:
        print("[*] Parsing existing logcat...")
        token_data = extract_token_from_logcat(device=args.device)

    if not token_data["bearer_token"]:
        print("[!] No Bearer token found in logcat.")
        print("[!] Make sure the Zeekr app is logged in and try again.")
        sys.exit(1)

    print(f"[*] Login server: {token_data['login_server']}")
    print(f"[*] User ID: {token_data.get('user_id', 'unknown')}")

    email = args.email or "owner"
    session = build_session(token_data, email)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump(session, f, indent=2)

    print(f"\n[OK] Session saved to: {args.output}")
    print(f"     Region: {session['region_code']}")
    print(f"     Server: {token_data['login_server']}")
    print(f"\nNext step: copy {args.output} to the project root and run:")
    print(f"  python dashboard.py")


if __name__ == "__main__":
    main()
