"""
debug.py — تحلیل آماری REALITY short-id ها
"""

import yaml
from pathlib import Path
from collections import Counter

PROFILE = Path("output/profile.yaml")

raw = PROFILE.read_text(encoding="utf-8")
yaml_text = "\n".join(ln for ln in raw.splitlines() if not ln.startswith("#"))
config = yaml.safe_load(yaml_text)

proxies = config.get("proxies", [])
print(f"کل proxy ها: {len(proxies)}\n")

# آمار طول short-id ها
length_counter = Counter()
sample_by_length = {}

for i, p in enumerate(proxies):
    if p.get("type") != "vless":
        continue
    ro = p.get("reality-opts")
    if not isinstance(ro, dict):
        continue
    
    sid = ro.get("short-id", "")
    if not isinstance(sid, str):
        sid = str(sid)
    
    length = len(sid)
    length_counter[length] += 1
    
    # نمونه ذخیره کن
    if length not in sample_by_length:
        sample_by_length[length] = (i+1, sid, p.get("name", "?")[:40])

print("=" * 70)
print("توزیع طول REALITY short-id ها:")
print("=" * 70)
for length in sorted(length_counter.keys()):
    count = length_counter[length]
    num, sid, name = sample_by_length[length]
    bytes_len = length // 2
    print(f"  طول {length:>2} hex ({bytes_len} بایت) → {count:>4} proxy   نمونه #{num}: {sid!r}")

print("\n" + "=" * 70)
print("طول‌های استاندارد Mihomo REALITY: 0, 2, 4, 8, 16 hex")
print("=" * 70)

# پیدا کردن proxy هایی با طول غیر استاندارد
STANDARD_LENGTHS = {0, 2, 4, 8, 16}
non_standard = []

for i, p in enumerate(proxies):
    if p.get("type") != "vless":
        continue
    ro = p.get("reality-opts")
    if not isinstance(ro, dict):
        continue
    
    sid = ro.get("short-id", "")
    if not isinstance(sid, str):
        sid = str(sid)
    
    if len(sid) not in STANDARD_LENGTHS:
        non_standard.append((i+1, sid, p.get("name", "?")[:40]))

print(f"\nتعداد proxy با طول غیر استاندارد: {len(non_standard)}")
if non_standard:
    print("\nنمونه‌ها (حداکثر 20 تا):")
    for num, sid, name in non_standard[:20]:
        print(f"  #{num} | len={len(sid):>2} | {sid!r} | {name}")
