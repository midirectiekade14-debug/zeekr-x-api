#!/usr/bin/env python3
"""
Zeekr APK Key Extractor
Extracts API signing keys from the Zeekr Android APK.

Usage:
    python tools/extract_keys.py <path-to-apk-or-xapk>

Requirements:
    - Python 3.10+
    - No extra dependencies (stdlib only)

What it extracts:
    - HMAC Access Key (from libHttpSecretKey.so)
    - HMAC Secret Key (from libAppSecret.so)
    - RSA Public Key for password encryption (from DEX files)
    - PROD Signing Key / X-SIGNATURE secret (from DEX files)
    - VIN AES Key + IV (from libcrypto-util.so)
"""

import io
import os
import re
import struct
import sys
import zipfile
import tempfile
import shutil

# --- Pattern definitions ---

# 32-char hex strings are candidate HMAC/signing keys
HEX32_RE = re.compile(rb"[0-9a-f]{32}")

# RSA public key markers (base64-encoded DER)
RSA_MARKERS = [
    b"MIICIjAN",   # RSA-4096 PKCS#8
    b"MIIBIjAN",   # RSA-2048 PKCS#8
    b"MIGfMA0",    # RSA-1024 PKCS#8
    b"-----BEGIN PUBLIC KEY-----",
    b"-----BEGIN RSA PUBLIC KEY-----",
]

# Known context strings that indicate where keys live
KEY_CONTEXTS = {
    b"libHttpSecretKey":   "HMAC Access Key (X-HMAC-ACCESS-KEY)",
    b"libAppSecret":       "HMAC Secret Key",
    b"libcrypto-util":     "VIN AES Key/IV",
    b"SignInterceptor":    "PROD Signing Key (X-SIGNATURE)",
    b"loginByEmailEncrypt": "RSA Public Key (password encryption)",
    b"X-HMAC-ACCESS-KEY":  "HMAC header reference",
    b"X-SIGNATURE":        "Signature header reference",
    b"hmac-sha256":        "HMAC algorithm reference",
}

# AES key/IV pattern: 16-char hex strings near crypto context
HEX16_RE = re.compile(rb"[0-9a-f]{16}")


def extract_apk_files(apk_path: str, tmp_dir: str) -> list[tuple[str, str]]:
    """Extract DEX and .so files from APK/XAPK."""
    files = []

    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            # Direct DEX files
            if name.endswith(".dex"):
                out = os.path.join(tmp_dir, name.replace("/", "_"))
                with z.open(name) as src, open(out, "wb") as dst:
                    dst.write(src.read())
                files.append(("APK/" + name, out))

            # Native libraries (.so)
            elif name.endswith(".so") and ("libHttp" in name or "libApp" in name or "libcrypto" in name):
                out = os.path.join(tmp_dir, os.path.basename(name))
                with z.open(name) as src, open(out, "wb") as dst:
                    dst.write(src.read())
                files.append(("APK/" + name, out))

            # Nested APKs (XAPK format)
            elif name.endswith(".apk"):
                nested_apk = os.path.join(tmp_dir, os.path.basename(name))
                with z.open(name) as src, open(nested_apk, "wb") as dst:
                    dst.write(src.read())
                try:
                    files.extend(extract_apk_files(nested_apk, tmp_dir))
                except zipfile.BadZipFile:
                    pass

            # Encrypted DEX bundles (.i.dex)
            elif name.endswith(".i.dex") or name.endswith("-sec.dex"):
                bundle = os.path.join(tmp_dir, os.path.basename(name))
                with z.open(name) as src, open(bundle, "wb") as dst:
                    dst.write(src.read())
                try:
                    with zipfile.ZipFile(bundle, "r") as inner:
                        for inner_name in inner.namelist():
                            if inner_name.endswith(".dex"):
                                out = os.path.join(tmp_dir, f"{name}__{inner_name}".replace("/", "_"))
                                with inner.open(inner_name) as isrc, open(out, "wb") as idst:
                                    idst.write(isrc.read())
                                files.append((f"APK/{name}/{inner_name}", out))
                except zipfile.BadZipFile:
                    files.append(("APK/" + name, bundle))

    return files


def search_file(filepath: str, source_name: str) -> dict:
    """Search a single file for keys and context strings."""
    findings = {}

    with open(filepath, "rb") as f:
        data = f.read()

    # Search for RSA public keys
    for marker in RSA_MARKERS:
        pos = 0
        while True:
            idx = data.find(marker, pos)
            if idx == -1:
                break
            # Extract base64 content (until non-base64 char)
            end = idx
            while end < len(data) and chr(data[end]) in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=\n\r":
                end += 1
            key_b64 = data[idx:end].decode("ascii", errors="ignore").replace("\n", "").replace("\r", "")
            if len(key_b64) > 100:  # Real RSA keys are long
                findings.setdefault("RSA_PUBLIC_KEY", []).append({
                    "source": source_name,
                    "offset": idx,
                    "value": key_b64[:120] + "..." if len(key_b64) > 120 else key_b64,
                    "full_value": key_b64,
                    "length": len(key_b64),
                })
            pos = idx + 1

    # Search for context strings and nearby hex keys
    for ctx_bytes, description in KEY_CONTEXTS.items():
        pos = 0
        while True:
            idx = data.find(ctx_bytes, pos)
            if idx == -1:
                break
            # Look for 32-char hex strings within 500 bytes
            window = data[max(0, idx - 200):idx + 500]
            for match in HEX32_RE.finditer(window):
                hex_val = match.group().decode("ascii")
                findings.setdefault("HEX_KEYS", []).append({
                    "source": source_name,
                    "context": description,
                    "context_offset": idx,
                    "value": hex_val,
                })

            # Look for 16-char hex strings (AES keys/IVs) near crypto-util
            if b"crypto" in ctx_bytes.lower():
                for match in HEX16_RE.finditer(window):
                    hex_val = match.group().decode("ascii")
                    # Filter out common false positives
                    if not all(c == hex_val[0] for c in hex_val):
                        findings.setdefault("AES_KEYS", []).append({
                            "source": source_name,
                            "context": description,
                            "value": hex_val,
                        })

            pos = idx + 1

    # Search for PROD signing key pattern (32-char hex near "PROD" or "SignInterceptor")
    for marker in [b"PROD", b"prod_secret", b"SIGN_KEY", b"sign_key"]:
        pos = 0
        while True:
            idx = data.find(marker, pos)
            if idx == -1:
                break
            window = data[max(0, idx - 100):idx + 200]
            for match in HEX32_RE.finditer(window):
                hex_val = match.group().decode("ascii")
                findings.setdefault("SIGNING_KEYS", []).append({
                    "source": source_name,
                    "context": f"Near '{marker.decode()}'",
                    "value": hex_val,
                })
            pos = idx + 1

    return findings


def deduplicate(findings: dict) -> dict:
    """Remove duplicate findings."""
    for key in findings:
        seen = set()
        unique = []
        for item in findings[key]:
            sig = (item.get("value", ""), item.get("context", ""))
            if sig not in seen:
                seen.add(sig)
                unique.append(item)
        findings[key] = unique
    return findings


def main():
    if len(sys.argv) < 2:
        print("Usage: python tools/extract_keys.py <path-to-apk-or-xapk>")
        print()
        print("Downloads the Zeekr APK from your phone or APKMirror,")
        print("then run this tool to extract the API signing keys.")
        sys.exit(1)

    apk_path = sys.argv[1]
    if not os.path.isfile(apk_path):
        print(f"Error: File not found: {apk_path}")
        sys.exit(1)

    print(f"Extracting keys from: {apk_path}")
    print(f"File size: {os.path.getsize(apk_path) / 1024 / 1024:.1f} MB")
    print()

    tmp_dir = tempfile.mkdtemp(prefix="zeekr_extract_")
    try:
        # Extract files
        print("Extracting APK contents...")
        files = extract_apk_files(apk_path, tmp_dir)
        print(f"Found {len(files)} searchable files (DEX + native libs)")
        print()

        # Search all files
        all_findings = {}
        for source_name, filepath in files:
            findings = search_file(filepath, source_name)
            for key, items in findings.items():
                all_findings.setdefault(key, []).extend(items)

        all_findings = deduplicate(all_findings)

        # Display results
        print("=" * 70)
        print("EXTRACTION RESULTS")
        print("=" * 70)

        if not any(all_findings.values()):
            print("\nNo keys found. The APK might use a different obfuscation method.")
            print("Try using jadx to decompile and search manually.")
            sys.exit(1)

        # RSA Public Key
        if "RSA_PUBLIC_KEY" in all_findings:
            print("\n--- RSA PUBLIC KEY (password encryption) ---")
            for item in all_findings["RSA_PUBLIC_KEY"]:
                print(f"  Source: {item['source']} @ offset {item['offset']}")
                print(f"  Length: {item['length']} chars")
                print(f"  Value:  {item['value']}")
                print()

        # HMAC / Signing keys
        if "HEX_KEYS" in all_findings:
            print("\n--- HMAC / API KEYS (32-char hex) ---")
            for item in all_findings["HEX_KEYS"]:
                print(f"  {item['context']}")
                print(f"  Source: {item['source']}")
                print(f"  Value:  {item['value']}")
                print()

        # AES keys
        if "AES_KEYS" in all_findings:
            print("\n--- AES KEYS (VIN encryption) ---")
            for item in all_findings["AES_KEYS"]:
                print(f"  {item['context']}")
                print(f"  Source: {item['source']}")
                print(f"  Value:  {item['value']}")
                print()

        # Signing keys
        if "SIGNING_KEYS" in all_findings:
            print("\n--- PROD SIGNING KEYS ---")
            for item in all_findings["SIGNING_KEYS"]:
                print(f"  {item['context']}")
                print(f"  Source: {item['source']}")
                print(f"  Value:  {item['value']}")
                print()

        # Summary for const.py
        print("=" * 70)
        print("COPY TO src/zeekr_ev_api/const.py:")
        print("=" * 70)
        print()

        hmac_keys = all_findings.get("HEX_KEYS", [])
        aes_keys = all_findings.get("AES_KEYS", [])
        rsa_keys = all_findings.get("RSA_PUBLIC_KEY", [])
        sign_keys = all_findings.get("SIGNING_KEYS", [])

        for item in hmac_keys:
            if "Access" in item["context"]:
                print(f'HMAC_ACCESS_KEY = "{item["value"]}"')
            elif "Secret" in item["context"]:
                print(f'HMAC_SECRET_KEY = "{item["value"]}"')

        for item in sign_keys:
            print(f'PROD_SECRET = "{item["value"]}"')

        for item in rsa_keys:
            print(f'PASSWORD_PUBLIC_KEY = "{item["full_value"]}"')

        if aes_keys:
            keys = [k["value"] for k in aes_keys]
            if len(keys) >= 2:
                print(f'VIN_KEY = "{keys[0]}"')
                print(f'VIN_IV = "{keys[1]}"')

        print()

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


if __name__ == "__main__":
    main()
