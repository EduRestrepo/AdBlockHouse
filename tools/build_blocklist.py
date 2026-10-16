#!/usr/bin/env python3
"""Preprocess hosts/domain blocklists into a sorted truncated-FNV-1a hash blob
for the ESP32-C3 ad-blocker. Hashes live in flash and are binary-searched on the
device, so no PSRAM is needed.

HASH_BYTES MUST match the firmware (src/main.cpp). 5 bytes (40-bit) keeps
~0 collisions up to ~500k domains while fitting half a million in <3 MB.

Usage: build_blocklist.py [out.bin] [src ...]
  src = local file or URL. With none given, downloads a balanced daily-driver set
  (StevenBlack base + Hagezi Pro) ~= 200k domains: blocks ads/trackers/malware
  but leaves WhatsApp/Instagram/social/messaging working.

  For the aggressive "test the limits" build (~500k, also blocks social/messaging):
    build_blocklist.py blocklist.bin \\
      https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/fakenews-gambling-porn-social/hosts \\
      https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/ultimate.txt
"""
import sys, os, math, urllib.request

HASH_BYTES = 5                          # 40-bit hashes -- must match firmware
MASK = (1 << (HASH_BYTES * 8)) - 1
FNV_OFFSET = 0xcbf29ce484222325
FNV_PRIME  = 0x100000001b3
U64 = (1 << 64) - 1

# Daily driver that FITS alongside dual-OTA firmware slots (~250k domain budget):
# ads + trackers + malware, WhatsApp/social keep working. ~140k domains / 0.67 MB.
# Want more (up to ~250k)? swap light.txt -> pro.txt is 370k and ONLY fits the
MAX_FLASH_BYTES = 2700000             # LittleFS partition limit (0x2A0000 = 2.75 MB)
MAX_CAPACITY_DOMAINS = MAX_FLASH_BYTES // HASH_BYTES  # ~540k domains max

DEFAULT_SOURCES = [
    'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts',                         # base: ads + malware
    'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/wildcard/pro.plus-onlydomains.txt', # HaGeZi Multi PRO++
    'https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt',                       # AdGuard DNS Filter (essential for web tests)
]

# Explicit exclusions for critical news/media paywall & user session systems
DEFAULT_EXCLUSIONS = {
    'piano.io',                 # Piano.io paywall & reading engine (El Espectador, etc.)
    'cdn.piano.io',
    'buy.piano.io',
    'mas.protecmedia.com',      # Protecmedia MAS: User auth & paywall (El Colombiano, etc.)
    'protecmedia.com',
}


def fnv(b: bytes) -> int:
    h = FNV_OFFSET
    for c in b:
        h = ((h ^ c) * FNV_PRIME) & U64
    return h & MASK                      # truncate to HASH_BYTES

def norm(d: str) -> str:
    d = d.strip().lower()
    if d.startswith('||'):
        d = d[2:]
    for sep in ('^', '$', '/', '#'):
        if sep in d:
            d = d.split(sep, 1)[0]
    d = d.lstrip('*').lstrip('.').rstrip('.')
    return d[4:] if d.startswith('www.') else d

def read_source(src: str) -> str:
    if os.path.exists(src):
        return open(src, errors='ignore').read()
    print(f'  downloading {src} ...', file=sys.stderr)
    req = urllib.request.Request(src, headers={'User-Agent': 'Mozilla/5.0 (compatible; AdBlockHouse/1.0)'})
    return urllib.request.urlopen(req, timeout=180).read().decode('utf-8', 'ignore')

def main():
    args = sys.argv[1:]
    out = args[0] if args else 'blocklist.bin'
    sources = args[1:] if len(args) > 1 else DEFAULT_SOURCES

    domains = set()
    for src in sources:
        try:
            data = read_source(src)
        except Exception as e:
            print(f'  !! skipped {src}: {e}', file=sys.stderr); continue
        for line in data.splitlines():
            line = line.split('#', 1)[0].strip()
            if not line or line[0] in '!/' or line.startswith('@@'):
                continue
            parts = line.split()
            d = parts[1] if len(parts) >= 2 and parts[0] in ('0.0.0.0','127.0.0.1','::1','::') \
                else parts[0] if len(parts) == 1 else None
            if d:
                d = norm(d)
                if '.' in d and ' ' not in d and d not in DEFAULT_EXCLUSIONS and not any(c in d for c in ('*', '/', ':', '$', '^', '|')):
                    domains.add(d)

    hashes = sorted(fnv(d.encode()) for d in domains)
    collisions = len(hashes) - len(set(hashes))
    uniq = sorted(set(hashes))                       # one entry per distinct hash

    if len(uniq) > MAX_CAPACITY_DOMAINS:
        print(f'  !! WARNING: {len(uniq):,} entries exceeds LittleFS capacity ({MAX_CAPACITY_DOMAINS:,}). Capping at limit.', file=sys.stderr)
        uniq = uniq[:MAX_CAPACITY_DOMAINS]

    with open(out, 'wb') as f:
        for h in uniq:
            f.write(h.to_bytes(HASH_BYTES, 'little'))

    n, size = len(uniq), len(uniq) * HASH_BYTES
    print(f'source domains   : {len(domains):,}')
    print(f'hash entries     : {n:,}  ({HASH_BYTES}-byte / {HASH_BYTES*8}-bit)')
    print(f'collisions       : {collisions}  (domains sharing a hash -> over-block)')
    print(f'flash blob       : {size:,} bytes  ({size/1024/1024:.2f} MB)  -> {out}')
    print(f'lookup           : ~{math.ceil(math.log2(max(n,2)))} reads/query')

if __name__ == '__main__':
    main()
