#!/usr/bin/env python3
"""Cross-checks the plugin's Lua MMDB reader against python-maxminddb.

usage: tools/crosscheck.py <database.mmdb> [samples=2000] [seed=1]

Picks addresses inside networks that exist in the database plus random IPv4
and IPv6 addresses, decodes each with both implementations and reports every
difference. Requires `pip install maxminddb` and OpenResty's (or Kong's)
`resty` on PATH. Run from the repository root.

Known, documented differences are tolerated: integers above 2^53 are compared
as doubles (Lua numbers), and IPv4-mapped IPv6 addresses are looked up as IPv4
(the plugin normalises them).
"""
import ipaddress, json, math, os, random, subprocess, sys, tempfile
import maxminddb

def norm(v):
    """Represents strings and bytes as one code point per byte (see mmdb-dump.lua)."""
    if isinstance(v, bool) or v is None:
        return v
    if isinstance(v, str):
        return v.encode("utf-8").decode("latin-1")
    if isinstance(v, (bytes, bytearray)):
        return bytes(v).decode("latin-1")
    if isinstance(v, dict):
        return {norm(k): norm(x) for k, x in v.items()}
    if isinstance(v, list):
        return [norm(x) for x in v]
    return v

def same(a, b):
    if isinstance(a, bool) or isinstance(b, bool):
        return a is b
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        if isinstance(a, float) and isinstance(b, float) and math.isnan(a) and math.isnan(b):
            return True
        if math.isinf(float(a)) or math.isinf(float(b)):
            return float(a) == float(b)
        if abs(a) > 2**53 or abs(b) > 2**53:
            return math.isclose(float(a), float(b), rel_tol=1e-12)
        return float(a) == float(b)
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(same(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(same(x, y) for x, y in zip(a, b))
    return a == b

def main():
    path = sys.argv[1]
    samples = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
    rnd = random.Random(int(sys.argv[3]) if len(sys.argv) > 3 else 1)
    reader = maxminddb.open_database(path, maxminddb.MODE_MMAP)
    v4only = reader.metadata().ip_version == 4
    ips, nets = [], 0
    try:
        for net, _ in reader:
            nets += 1
            if rnd.random() < 0.02 or nets < 50:
                first = int(net.network_address)
                off = rnd.randrange(net.num_addresses) if net.num_addresses > 1 else 0
                ips.append(str(ipaddress.ip_address(first + off)))
            if len(ips) >= samples // 2:
                break
    except Exception as e:  # python-maxminddb cannot iterate some synthetic test files
        print(f"note: network iteration stopped early ({e.__class__.__name__}); using random addresses")
    while len(ips) < samples:
        if rnd.random() < 0.7:
            ips.append(str(ipaddress.IPv4Address(rnd.getrandbits(32))))
        else:
            ips.append(str(ipaddress.IPv6Address(rnd.getrandbits(128))))
    ips += ["::ffff:" + ip for ip in ips[:20] if ":" not in ip]
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write("\n".join(ips) + "\n")
        listfile = f.name
    out = subprocess.run(["resty", "-I", ".", "tools/mmdb-dump.lua", path, listfile],
                         capture_output=True, text=True, encoding="utf-8")
    if out.returncode != 0:
        print(out.stderr)
        sys.exit(2)
    lines = [json.loads(l) for l in out.stdout.splitlines() if l.strip()]
    mismatches = found = errors_both = 0
    for ip, got in zip(ips, lines):
        lookup_ip = ip[7:] if ip.startswith("::ffff:") and "." in ip else ip
        try:
            exp, _ = reader.get_with_prefix_len(lookup_ip)
        except ValueError:
            # IPv6 address in an IPv4-only database: the plugin must report an error too
            if "error" in got:
                errors_both += 1
            else:
                mismatches += 1
                print("MISMATCH (expected an error)", ip, json.dumps(got)[:200])
            continue
        if exp is not None:
            found += 1
        if "error" in got or not same(got.get("record"), norm(exp)):
            mismatches += 1
            if mismatches <= 5:
                print("MISMATCH", ip, json.dumps(got)[:300], "| expected:", repr(exp)[:300])
    extra = f", {errors_both} rejected by both (IPv6 in IPv4-only database)" if v4only else ""
    print(f"{os.path.basename(path)}: {len(ips)} addresses, {found} with records, {mismatches} mismatches{extra}")
    sys.exit(1 if mismatches else 0)

if __name__ == "__main__":
    main()
