#!/usr/bin/env python3
"""
check_threats.py

Usage:
  python check_threats.py <hash1> [hash2 ...]
  python check_threats.py --scan

Environment:
  VT_API_KEY must be set (GitHub secret or local environment)
"""

import os
import sys
import requests
import hashlib
from pathlib import Path
from typing import List, Set

VT_API_ENV = "VT_API_KEY"
VT_BASE = "https://www.virustotal.com/api/v3/files/"
TIMEOUT = 20
SKIP_DIRS = {".git", "venv", "__pycache__", ".github"}

def get_api_key() -> str:
    key = os.environ.get(VT_API_ENV)
    if not key:
        print(f"❌ Error: environment variable {VT_API_ENV} not found. Exiting.")
        sys.exit(1)
    return key

def check_hash(api_key: str, file_hash: str) -> dict:
    url = VT_BASE + file_hash
    headers = {"x-apikey": api_key}
    try:
        r = requests.get(url, headers=headers, timeout=TIMEOUT)
    except requests.RequestException as e:
        return {"hash": file_hash, "error": f"Request error: {e}"}
    if r.status_code == 200:
        data = r.json()
        attrs = data.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "hash": file_hash,
            "malicious": int(stats.get("malicious", 0)),
            "suspicious": int(stats.get("suspicious", 0)),
            "harmless": int(stats.get("harmless", 0))
        }
    else:
        return {"hash": file_hash, "error": f"HTTP {r.status_code} - {r.text[:200]}"}

def compute_sha256_for_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def gather_file_hashes(root: Path) -> Set[str]:
    hashes = set()
    for p in root.rglob("*"):
        if p.is_dir() or set(p.parts) & SKIP_DIRS:
            continue
        try:
            sha = compute_sha256_for_file(p)
            hashes.add(sha)
            print(f"Found file: {p} -> {sha}")
        except Exception as e:
            print(f"Skipped {p}: {e}")
    return hashes

def print_result(res: dict):
    if "error" in res:
        print(f"❌ {res['hash']}: {res['error']}")
    else:
        mal = res.get("malicious", 0)
        sus = res.get("suspicious", 0)
        if mal > 0:
            print(f"⚠️ MALICIOUS: {res['hash']} (malicious={mal}, suspicious={sus})")
        elif sus > 0:
            print(f"⚠️ SUSPICIOUS: {res['hash']} (malicious={mal}, suspicious={sus})")
        else:
            print(f"✅ SAFE: {res['hash']} (malicious={mal}, suspicious={sus})")

def main(argv: List[str]):
    api_key = get_api_key()
    if len(argv) >= 2 and argv[1] == "--scan":
        hashes = gather_file_hashes(Path.cwd())
        if not hashes:
            print("No files found to scan.")
            sys.exit(0)
        to_check = sorted(hashes)
    elif len(argv) >= 2:
        to_check = argv[1:]
    else:
        print("Usage: python check_threats.py <hash1> [hash2 ...] OR --scan")
        sys.exit(1)

    any_malicious = False
    for h in to_check:
        print(f"\nChecking: {h}")
        res = check_hash(api_key, h)
        print_result(res)
        if res.get("malicious", 0) > 0:
            any_malicious = True

    if any_malicious:
        print("\n❗ ONE OR MORE MALICIOUS ITEMS FOUND.")
        sys.exit(1)
    else:
        print("\n✅ No malicious items detected.")
        sys.exit(0)

if __name__ == "__main__":
    main(sys.argv)
